'''
This file is part of sigcheck.

sigcheck is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

sigcheck is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with sigcheck.  If not, see <https://www.gnu.org/licenses/>.

---

Volatility 3 port of the sigcheck plugin (originally written for Volatility 2.6).
It verifies Authenticode digital signatures of executable files (.exe, .dll, .sys)
reconstructed from cached file objects in a Windows memory image.
'''

import os
import re
import json
import struct
import logging

import pefile

# Ensure the sibling sigvalidator module (shipped alongside this plugin) is importable
# regardless of how Volatility 3 loaded this file.
import sys
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import sigvalidator

from enum import Enum
from typing import List

from volatility3.framework import interfaces, renderers, exceptions
from volatility3.framework.configuration import requirements
from volatility3.plugins.windows import pslist, modules, filescan

vollog = logging.getLogger(__name__)


class ReturnCode(Enum):
    FILEOBJECT_ERROR = (1, 'Unable to read FileObject')
    PE_REBUILT_FAILED = (2, 'Unable to rebuild PE file')
    PE_CHECKSUM_MISMATCH = (3, 'PE OptionalHeader.CheckSum mismatch')
    PARTIAL_CONTENT_PE_DATA_ERROR = (4, 'Partial file content. Unable to load PE')
    SIGNED_FILE_NOT_VERIFIED = (5, 'Signed file, but not verified')
    CONTENT_SIGNED_NOT_VERIFIED = (6, 'Partial file content. Signed file, but not verified')
    PARTIAL_CONTENT_MAYBE_CATALOG_SIGNED = (7, 'Partial file content. Not signed file (maybe catalog-signed?)')
    PARTIAL_CONTENT_NOT_SIGNED = (8, 'Partial file content. Not signed file')
    AUTHENTICODE_SIGNATURE_MISMATCH_OR_INCORRECT_IMAGEBASE = (9, 'Certificate\'s hash mismatch calculated hash, or incorrect ImageBase during reconstruction')
    AUTHENTICODE_SIGNATURE_MISMATCH = (10, 'Certificate\'s hash mismatch calculated hash')
    CATALOG_SIGNED = (11, 'Verification successful (catalog-signed)')
    MAYBE_CATALOG_SIGNED = (12, 'Not signed file (maybe catalog-signed?)')
    NOT_SIGNED_OR_INCORRECT_IMAGEBASE = (13, 'Not signed file, or incorrect ImageBase during reconstruction')
    NOT_SIGNED = (14, 'Not signed file')
    NOT_PEB = (15, 'Unable to read PEB')
    ALREADY_TERMINATED = (16, 'Already terminated')
    PARTIAL_CERTIFICATE = (17, 'Embedded certificate incomplete')
    PARTIAL_CONTENT_VERIFIED = (18, 'Partial file content. Unable to compare file hash and signature hash')

    def __int__(self):
        return self.value[0]

    def __str__(self):
        return self.value[1]


class SigCheck(interfaces.plugins.PluginInterface):
    '''Validates Authenticode-signed executables (embedded or catalog-signed) in a memory image.'''

    _required_framework_version = (2, 0, 0)
    _version = (1, 0, 0)

    @classmethod
    def get_requirements(cls) -> List[interfaces.configuration.RequirementInterface]:
        return [
            requirements.ModuleRequirement(
                name='kernel',
                description='Windows kernel',
                architectures=['Intel32', 'Intel64'],
            ),
            requirements.VersionRequirement(
                name='pslist', component=pslist.PsList, version=(3, 0, 0)),
            requirements.VersionRequirement(
                name='modules', component=modules.Modules, version=(3, 0, 0)),
            requirements.VersionRequirement(
                name='filescan', component=filescan.FileScan, version=(2, 0, 0)),
            requirements.StringRequirement(
                name='catalog',
                description='Directory containing catalog files (.cat) to look signatures into',
                optional=True,
                default=None,
            ),
            requirements.BooleanRequirement(
                name='dll',
                description='Verify library modules (.dll) too',
                default=False,
                optional=True,
            ),
            requirements.BooleanRequirement(
                name='sys',
                description='Verify driver modules (.sys)',
                default=False,
                optional=True,
            ),
        ]

    # ------------------------------------------------------------------ helpers

    def _get_directory_file(self, filename):
        return os.path.join(os.path.dirname(os.path.abspath(__file__)), filename)

    def load_json(self, path):
        with open(path, 'r') as f:
            return json.load(f)

    def load_frequent_addresses(self):
        '''
        Loads addresses.json and merges the most frequent ImageBases of every
        bundled profile into a single {exe,dll,sys -> [imagebases]} mapping.

        Volatility 3 has no profile string, so instead of selecting one profile we
        merge them: the reconstruction loop already filters candidates by bitness and
        stops at the first one whose checksum matches.
        '''

        try:
            data = self.load_json(self._get_directory_file('addresses.json'))
        except IOError:
            vollog.warning('Unable to load most frequent addresses (addresses.json)')
            return {}

        merged = {}
        for profile in sorted(data.keys()):
            for file_type, addresses in data[profile].items():
                bucket = merged.setdefault(file_type, [])
                for address in addresses:
                    if address not in bucket:
                        bucket.append(address)

        return merged

    # ------------------------------------------------------------ enumeration

    def _read_dllname(self, entry, attr):
        try:
            return getattr(entry, attr).get_string()
        except exceptions.InvalidAddressException:
            return None

    def get_modules(self):
        '''
        Returns a list of (full_path, base_name, pid) tuples for the modules to verify,
        depending on the selected options (exe by default, --dll, or --sys).
        '''

        ret = []
        kernel_name = self.config['kernel']

        if self.config['sys']:
            for mod in modules.Modules.list_modules(self.context, kernel_name):
                full = self._read_dllname(mod, 'FullDllName')
                base = self._read_dllname(mod, 'BaseDllName')
                ret.append((full, base, 0))
        else:
            for proc in pslist.PsList.list_processes(self.context, kernel_name):
                try:
                    pid = int(proc.UniqueProcessId)
                    proc.add_process_layer()
                    mods = list(proc.load_order_modules())
                except exceptions.InvalidAddressException:
                    continue

                if self.config['dll']:
                    for entry in mods:
                        full = self._read_dllname(entry, 'FullDllName')
                        base = self._read_dllname(entry, 'BaseDllName')
                        ret.append((full, base, pid))
                elif mods:
                    # First module in InLoadOrderModuleList is the process image (.exe)
                    entry = mods[0]
                    full = self._read_dllname(entry, 'FullDllName')
                    base = self._read_dllname(entry, 'BaseDllName')
                    ret.append((full, base, pid))

        return ret

    def get_file_objects(self):
        '''
        Scans the image for all FileObjects (using the FileScan plugin) and keeps the
        ones with a readable name, so we can later match modules against them.
        '''

        vollog.info('Retrieving all file objects, this may take a while...')

        ret = []
        for fileobj in filescan.FileScan.scan_files(self.context, self.config['kernel']):
            try:
                name = fileobj.file_name_with_device()
            except exceptions.InvalidAddressException:
                continue
            if not isinstance(name, str):
                continue
            ret.append({'name': name, 'fobj': fileobj})

        return ret

    # ------------------------------------------------------- content extraction

    def get_file_object(self, filename):
        '''
        Finds the FileObject matching an executable full path and reconstructs its content.

        @return (is_complete, file_object dict) or (False, None)
        '''

        if not filename:
            return False, None

        filename = self.normalize_filepath(filename)
        if not filename:
            return False, None

        for f in self.files:
            # Same file if executable path and file object path match
            if re.match(r'^{0}$'.format(filename), f['name'], flags=re.IGNORECASE):
                return self.extract_object(f)

        return False, None

    def normalize_filepath(self, filepath):
        '''
        Converts a module path to the uniform \\Device\\HarddiskVolumeX notation used by
        FileObject names, returning a regex pattern. Returns None if no conversion applies.
        '''

        # Ordered from most to least specific: '\\?\C:' must be tried before 'C:'.
        to_replace = [
            ('\\SystemRoot', '\\\\Device\\\\HarddiskVolume[0-9]\\\\Windows'),
            ('\\\\\\?\\C:', '\\\\Device\\\\HarddiskVolume[0-9]'),
            ('C:', '\\\\Device\\\\HarddiskVolume[0-9]'),
        ]

        for key, replacement in to_replace:
            path = filepath.split(key)
            if len(path) == 2:
                return replacement + re.escape(path[1])

        return None

    def extract_object(self, file_object):
        '''
        Reconstructs the cached content of a FileObject from its DataSectionObject and
        ImageSectionObject control areas (same data DumpFiles would carve).

        Mirrors the original plugin: prefer a fully memory-resident (complete) cache;
        otherwise fall back to a partial one. DataSectionObject is preferred over
        ImageSectionObject because it is stored with the on-disk layout.

        @return (is_complete, file_object dict with keys name/type/content) or (False, None)
        '''

        kernel = self.context.modules[self.config['kernel']]
        memory_layer_name = self.context.layers[kernel.layer_name].config['memory_layer']
        memory_layer = self.context.layers[memory_layer_name]

        candidates = []
        for member_name in ('DataSectionObject', 'ImageSectionObject'):
            try:
                section_obj = getattr(file_object['fobj'].SectionObjectPointer, member_name)
                control_area = section_obj.dereference().cast('_CONTROL_AREA')
                if not control_area.is_valid():
                    continue
            except exceptions.InvalidAddressException:
                continue

            content, complete = self.reconstruct_content(control_area, memory_layer)
            if content is None:
                continue

            candidates.append({
                'name': file_object['name'],
                'type': member_name,
                'content': content,
                'complete': complete,
            })

        # SharedCacheMap is intentionally not supported (as in the original plugin)
        for candidate in candidates:
            if candidate['complete']:
                return True, candidate
        if candidates:
            return False, candidates[0]

        return False, None

    def reconstruct_content(self, control_area, memory_layer):
        '''
        Rebuilds a file buffer from the available cached pages of a control area.

        A page that is missing in the middle of the file marks the buffer as partial.
        (Trailing missing pages cannot be detected this way and would look complete; this
        matches the inherent limitation of working from resident pages only.)

        @return (bytes content, bool complete) or (None, False)
        '''

        pages = list(control_area.get_available_pages())
        if not pages:
            return None, False

        expected_end = max(file_offset + size for (_phys, file_offset, size) in pages)
        data = bytearray(expected_end)
        present_pages = set()

        for phys_offset, file_offset, size in pages:
            try:
                chunk = memory_layer.read(phys_offset, size, pad=True)
            except exceptions.InvalidAddressException:
                continue
            data[file_offset:file_offset + len(chunk)] = chunk
            for page in range(file_offset, file_offset + size, 0x1000):
                present_pages.add(page // 0x1000)

        total_pages = (expected_end + 0xfff) // 0x1000
        complete = len(present_pages) == total_pages

        return bytes(data), complete

    # ------------------------------------------------------------- validation

    def validate_file(self, file_object):
        '''Validates the signature of a fully reconstructed FileObject.'''

        content = file_object['content']
        file_type = self.get_pe_type(file_object)

        # ImageSectionObject is relocated in memory; DataSectionObject keeps on-disk layout
        if file_object['type'] == 'ImageSectionObject':
            return self.validate_image_section(content, file_type)
        elif file_object['type'] == 'DataSectionObject':
            return self.validate_data_section(content)

    def get_pe_type(self, file_object):
        extension = file_object['name'].split('.')[-1].lower()

        if not self.config['sys'] and not self.config['dll']:
            return 'exe'
        elif self.config['sys']:
            return 'sys'
        elif self.config['dll']:
            return 'exe' if extension == 'exe' else 'dll'

        return extension

    def validate_image_section(self, content, file_type):
        content = self.delete_padding(content)
        pe = pefile.PE(data=content, fast_load=True)
        is_32bits = self.is_32bits(content)

        if pe.verify_checksum():
            return self.verify_pe(pe)

        if file_type in self.frequent_addresses:
            for new_imagebase in self.frequent_addresses[file_type]:
                new_imagebase = int(new_imagebase, 16)

                if is_32bits and new_imagebase > 0xffffffff:
                    continue

                try:
                    pe = pefile.PE(data=content, fast_load=True)
                    pe.relocate_image(new_imagebase)
                    new_content = self.set_imagebase(new_imagebase, pe.__data__)
                    pe = pefile.PE(data=new_content, fast_load=True)

                    if pe.verify_checksum():
                        return self.verify_pe(pe)
                # AttributeError: some PE files don't have a relocation table
                # struct.error: relocation can fail reading data during the process
                except (AttributeError, struct.error):
                    pass
        else:
            vollog.warning('\'%s\': file extension not supported for reconstruction', file_type)

        return ReturnCode.PE_REBUILT_FAILED

    def validate_data_section(self, content):
        '''Validates the signature of a DataSectionObject (on-disk layout).'''

        # Sometimes there is padding at the end of the buffer
        content = self.delete_padding(content)
        pe = pefile.PE(data=content, fast_load=True)

        # Ensure there are no extraction errors
        if pe.verify_checksum():
            # Files can have an embedded signature
            cert = self.sigv.extract_cert(pe)
            if cert:
                algorithm, hash_file = self.sigv.get_digest_from_signature(cert)
                if algorithm:
                    digest = self.sigv.calculate_pe_digest(algorithm, content)
                    if hash_file == digest:
                        return self.sigv.verify_signature(cert)
                    else:
                        return ReturnCode.AUTHENTICODE_SIGNATURE_MISMATCH
                else:
                    return ReturnCode.PARTIAL_CERTIFICATE
            # Or the signature can live in a separate catalog file
            else:
                for algorithm in ['md5', 'sha1', 'sha256']:
                    digest = self.sigv.calculate_pe_digest(algorithm, content)
                    if self.sigv.is_in_catalog(digest):
                        return ReturnCode.CATALOG_SIGNED
                return ReturnCode.NOT_SIGNED
        else:
            return ReturnCode.PE_CHECKSUM_MISMATCH

    def verify_pe(self, pe):
        cert = self.sigv.extract_cert(pe)
        if cert:
            algorithm, hash_file = self.sigv.get_digest_from_signature(cert)
            if algorithm:
                digest = self.sigv.calculate_pe_digest(algorithm, pe.__data__)
                if hash_file == digest:
                    return self.sigv.verify_signature(cert)
                else:
                    return ReturnCode.AUTHENTICODE_SIGNATURE_MISMATCH
            else:
                return ReturnCode.PARTIAL_CERTIFICATE
        else:
            for algorithm in ['md5', 'sha1', 'sha256']:
                digest = self.sigv.calculate_pe_digest(algorithm, pe.__data__)
                if self.sigv.is_in_catalog(digest):
                    return ReturnCode.CATALOG_SIGNED

            return ReturnCode.NOT_SIGNED

    def validate_partial_file(self, file_object):
        if not file_object:
            return ReturnCode.FILEOBJECT_ERROR

        content = file_object['content']
        try:
            pe = pefile.PE(data=content, fast_load=True)
            if self.sigv.has_cert(pe):
                if file_object['type'] == 'DataSectionObject':
                    cert = self.sigv.extract_cert(pe)
                    if cert:
                        return '{0!s}. Signature verification: {1}'.format(
                            ReturnCode.PARTIAL_CONTENT_VERIFIED, self.sigv.verify_signature(cert))
                    else:
                        return ReturnCode.CONTENT_SIGNED_NOT_VERIFIED
                # SecurityDirectory entry is not mapped into memory in ImageSectionObject
                elif file_object['type'] == 'ImageSectionObject':
                    return ReturnCode.CONTENT_SIGNED_NOT_VERIFIED
            else:
                # Microsoft programs under '\Windows' are usually catalog-signed
                if re.match(r'\\Device\\HarddiskVolume[0-9]\\Windows', file_object['name']):
                    return ReturnCode.PARTIAL_CONTENT_MAYBE_CATALOG_SIGNED

                return ReturnCode.PARTIAL_CONTENT_NOT_SIGNED
        except pefile.PEFormatError:
            return ReturnCode.PARTIAL_CONTENT_PE_DATA_ERROR

    # ----------------------------------------------------------- PE primitives

    def get_nt_header_addr(self, pe_data):
        if pe_data[:2] == b'\x4D\x5A':                  # MZ
            nt_headers_addr = self.unpack_dword(pe_data[0x3c:0x3c + 0x04])
            nt_headers = pe_data[nt_headers_addr:nt_headers_addr + 0x04]
            if nt_headers == b'\x50\x45\x00\x00':       # PE
                return nt_headers_addr

    def set_imagebase(self, imagebase, content):
        nt_headers_addr = self.get_nt_header_addr(content)

        if self.is_32bits(content):
            return content[:nt_headers_addr + 0x34] + self.pack_dword(imagebase) + content[nt_headers_addr + 0x34 + 0x4:]
        elif self.is_64bits(content):
            return content[:nt_headers_addr + 0x30] + self.pack_qword(imagebase) + content[nt_headers_addr + 0x30 + 0x8:]

    def is_32bits(self, content):
        nt_headers_addr = self.get_nt_header_addr(content)
        magic = content[nt_headers_addr + 0x18:nt_headers_addr + 0x18 + 0x2]
        return magic == b'\x0B\x01'

    def is_64bits(self, content):
        nt_headers_addr = self.get_nt_header_addr(content)
        magic = content[nt_headers_addr + 0x18:nt_headers_addr + 0x18 + 0x2]
        return magic == b'\x0B\x02'

    def unpack_dword(self, bytes_):
        return struct.unpack('<I', bytes_)[0]

    def pack_dword(self, value):
        return struct.pack('<I', value)

    def pack_qword(self, value):
        return struct.pack('<Q', value)

    def delete_padding(self, content):
        real_size = self.calculate_pe_size(content)
        return content[:real_size]

    def calculate_pe_size(self, data):
        '''Size of PE headers + all sections + Authenticode signature (if any).'''

        pe = pefile.PE(data=data, fast_load=True)
        size = pe.NT_HEADERS.OPTIONAL_HEADER.SizeOfHeaders
        for section in pe.sections:
            size += section.SizeOfRawData
        size += pe.OPTIONAL_HEADER.DATA_DIRECTORY[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_SECURITY']].Size
        return size

    # --------------------------------------------------------------- run / output

    def _generator(self):
        if self.config['dll'] and self.config['sys']:
            vollog.error('Incompatible options: use either --dll or --sys, not both')
            return

        catalog = self.config.get('catalog')
        if catalog and not os.path.isdir(catalog):
            vollog.warning('\'%s\': not a directory; catalog-signed verification disabled', catalog)
            catalog = None

        self.sigv = sigvalidator.SigValidator(catalog)
        self.frequent_addresses = self.load_frequent_addresses()
        self.already_analyzed = {}

        target_modules = self.get_modules()
        if not target_modules:
            return

        self.files = self.get_file_objects()

        for module_path, module_name, pid in target_modules:
            name = module_name if module_name else (module_path or 'UNKNOWN')

            if module_path in self.already_analyzed:
                yield (0, (str(name), int(pid), str(self.already_analyzed[module_path])))
                continue

            if not module_path:
                result = ReturnCode.NOT_PEB
            else:
                is_complete, file_object = self.get_file_object(module_path)
                if file_object is None:
                    result = ReturnCode.FILEOBJECT_ERROR
                elif is_complete:
                    result = self.validate_file(file_object)
                else:
                    result = self.validate_partial_file(file_object)
                self.already_analyzed[module_path] = result

            yield (0, (str(name), int(pid), str(result)))

    def run(self):
        return renderers.TreeGrid(
            [
                ('Module', str),
                ('Pid', int),
                ('Result', str),
            ],
            self._generator(),
        )

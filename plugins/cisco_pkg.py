from binwalk.core.compat import str2bytes
from binwalk.core.common import unique_file_name
from binwalk.core.plugin import Plugin
from binwalk.core.magic import SignatureResult

import os
from subprocess import call
from os.path import abspath, splitext, dirname
from struct import unpack, calcsize
from Crypto.Cipher import AES
from hashlib import sha256

'''
Plugin: Cisco Package File
File: ~/.config/binwalk/plugins/cisco_pkg.py
Author: @nezlooy
'''

SIG_DESCRIPTION = 'Cisco Package File'
MAGIC_NUMBER = 0xC5C0

# Magic number 2 bytes, version 4 bytes, number of sections 1 byte,
# format_type 1 byte, 8 bytes string for future use
PKG_HEADER_FORMAT = 'HiBB8s'
PKG_HEADER_SIZE = calcsize(PKG_HEADER_FORMAT)

# Section type 1 byte, section name 8 byte str, data size 4 bytes
SEC_HEADER_FORMAT = 'B11sI'
SEC_HEADER_SIZE = calcsize(SEC_HEADER_FORMAT)

BASE_PKG_TYPE = ord('r')
BASIC_PKG_TYPE = BASE_PKG_TYPE + 1
CHECKSUM_PKG_TYPE = BASE_PKG_TYPE + 2
SIGNED_CHECKSUM_PKG_TYPE = BASE_PKG_TYPE + 3
ENCRYPTED_CONTENT_CHECKSUM_PKG_TYPE = BASE_PKG_TYPE + 4
ENCRYPTED_CONTENT_SIGNED_CHECKSUM_PKG_TYPE = BASE_PKG_TYPE + 5

PKG_TYPES = {
	BASE_PKG_TYPE: 'Base Package',
	BASIC_PKG_TYPE: 'Basic Package',
	CHECKSUM_PKG_TYPE: 'Checksum Package',
	SIGNED_CHECKSUM_PKG_TYPE: 'Signed Checksum Package',
	ENCRYPTED_CONTENT_CHECKSUM_PKG_TYPE: 'Encrypted Content Checksum Package',
	ENCRYPTED_CONTENT_SIGNED_CHECKSUM_PKG_TYPE: 'Encrypted Content Signed Checksum Package'
}

SECTION_TYPE_ARCHIVE_TBZ2 = 0x0001
SECTION_TYPE_CHECKSUM = 0x0002
SECTION_TYPE_KEY = 0x0003
SECTION_TYPE_SIGNED_CHECKSUM = 0x0004
SECTION_TYPE_ENCRYPTED_ARCHIVE_TBZ2 = 0x0005

SECTION_TYPES = {
	SECTION_TYPE_ARCHIVE_TBZ2: 'Archive tbz2',
	SECTION_TYPE_CHECKSUM: 'Checksum',
	SECTION_TYPE_KEY: 'Key',
	SECTION_TYPE_SIGNED_CHECKSUM: 'Signed checksum',
	SECTION_TYPE_ENCRYPTED_ARCHIVE_TBZ2: 'Encrypted archive tbz2'
}

# Key used to encrypt the randomly generated key for encrypting db file
ENC_KEY = sha256(b'r4onxh8364&Jh^%P)Kqf65d6ev#^%#(&(;kuwtUTR-WQp%^#86').digest()

# Pre-generated on-box encryption key. This key is used to encrypt and decrypt the per package instance key.
# Cisco ToDo: This key should be moved to an external file or binary and should be retrieved from there.
ON_BOX_ENC_KEY = sha256(b'R4o0x~8d|4=Jh^%P)Kqf6d5e.v#^%#(&(;kuwtUTR-WQp%^#86').digest()


class Section(object):
	def __init__(self, fd):
		super(Section, self).__init__()
		self.fd = fd
		self.offset = fd.tell()
		self.type, self.name, self.size = unpack(SEC_HEADER_FORMAT, str2bytes(fd.read(SEC_HEADER_SIZE)))
		self.name = self.name.decode().strip('\x00')
		self.data_offset = self.offset + SEC_HEADER_SIZE
		self.is_encryped = self.type == SECTION_TYPE_ENCRYPTED_ARCHIVE_TBZ2
		self.data_size = self.real_size = self.size

		if self.is_encryped:
			self.real_size = unpack('<Q', str2bytes(fd.read(calcsize('Q'))))[0]
			self.vector = str2bytes(fd.read(16))
			self.hash = str2bytes(fd.read(56))
			self.data_offset = fd.tell()
			self.data_size -= self.data_offset - self.offset - SEC_HEADER_SIZE

		fd.seek(self.offset + SEC_HEADER_SIZE + self.size)

	@property
	def value(self):
		self.fd.seek(self.data_offset)
		return str2bytes(self.fd.read(self.data_size if self.is_encryped else self.size))

	def __repr__(self):
		return '<{}(type: {}, name: "{}", size: {})>'.format(self.__class__.__name__, 
			SECTION_TYPES.get(self.type, 'Unknown'), self.name, 
			self.origsize if self.is_encryped else self.size)


class PKGFile(object):
	key = None
	valid = True
	chunksize = 0x10000

	def __init__(self, fd):
		super(PKGFile, self).__init__()
		self.fd = fd
		magic, self.version, self.num_sections, self.type, _ = unpack(PKG_HEADER_FORMAT, str2bytes(fd.read(PKG_HEADER_SIZE)))
		assert magic == MAGIC_NUMBER

		self.sections = list(Section(fd) for _ in range(self.num_sections))
		if self.type in [ENCRYPTED_CONTENT_CHECKSUM_PKG_TYPE, ENCRYPTED_CONTENT_SIGNED_CHECKSUM_PKG_TYPE]:
			for sec in self.sections:
				if sec.type == SECTION_TYPE_KEY:
					decryptor = AES.new(ON_BOX_ENC_KEY, AES.MODE_CBC, '\x00' * 16)
					self.key = decryptor.decrypt(sec.value)
					break
			self.valid = self.key is not None

	def untar(self, tar_filename, out_dir):
		result = None
		try:
			fperr = open(os.devnull, 'rb')
			os.mkdir(out_dir)
		except OSError:
			return False
		try:
			result = call(['tar', '-xvf', tar_filename, '-C', out_dir], stderr=fperr, stdout=fperr)
		except OSError:
			result = -1
		fperr.close()
		return result == 0

	def extract(self):
		if not self.valid:
			return False

		for sec in self.sections:
			if sec.type in [SECTION_TYPE_ARCHIVE_TBZ2, SECTION_TYPE_ENCRYPTED_ARCHIVE_TBZ2]:
				self.fd.seek(sec.data_offset)
				
				if sec.type == SECTION_TYPE_ENCRYPTED_ARCHIVE_TBZ2:
					decryptor = AES.new(self.key, AES.MODE_CBC, sec.vector)

				out_filename = unique_file_name('{}_off{:X}.{}.tbz2'.format(abspath(self.fd.path), sec.offset, sec.name))
				with open(out_filename, 'w+b') as out_fd:
					n, cz = 0, self.chunksize
					while n < sec.data_size:
						n += cz
						if n > sec.data_size:
							cz -= n - sec.data_size
						chunk = str2bytes(self.fd.read(cz))
						if sec.type == SECTION_TYPE_ENCRYPTED_ARCHIVE_TBZ2:
							chunk = decryptor.decrypt(chunk)
						out_fd.write(chunk)

				self.untar(out_filename, splitext(out_filename)[0])

		return True

	@property
	def size(self):
		return PKG_HEADER_SIZE + sum(SEC_HEADER_SIZE + sec.size for sec in self.sections)

	def close(self):
		if not self.fd.closed:
			self.fd.close()

	def __enter__(self):
		return self

	def __exit__(self, exc_type, exc_val, exc_tb):
		self.close()
		if exc_val:
			raise

	def __repr__(self):
		return '<{}(type: {}, version: 0x{:X}, num_sections: {}, size: {})>'.format(self.__class__.__name__, 
			PKG_TYPES.get(self.type, 'Unknown'), self.version, self.num_sections, self.size)


class CiscoPkgExtractor(Plugin):
	MODULES = ['Signature']

	def init(self):
		if self.module.extractor.enabled:
			self.module.extractor.add_rule(txtrule=False, regex='^{}'.format(SIG_DESCRIPTION.lower()), extension='pkg', cmd=self.extractor)

	def extractor(self, fname):
		with PKGFile(self.module.config.open_file(abspath(fname))) as pkg:
			return pkg.extract()

	def scan(self, result):
		if result.valid and result.description.startswith(SIG_DESCRIPTION) and isinstance(result, SignatureResult):
			fd = self.module.config.open_file(abspath(result.file.path), offset=result.offset)
			with PKGFile(fd) as pkg:
				result.jump = result.offset + pkg.size

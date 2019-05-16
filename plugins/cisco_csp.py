from binwalk.core.compat import str2bytes, bytes2str
from binwalk.core.common import unique_file_name
from binwalk.core.plugin import Plugin
from binwalk.core.magic import SignatureResult

import os, json
from subprocess import call
from os.path import abspath
from struct import unpack, calcsize
# from Crypto.Cipher import AES
# from hashlib import sha256
from collections import namedtuple

'''
Plugin: Cisco CSP File
File: ~/.config/binwalk/plugins/cisco_csp.py
Author: @nezlooy
'''

SIG_DESCRIPTION = 'Cisco CSP File'


CSP_SIGNATURE_GUID = b'\x08\x8F\x2A\x54\x79\x99\x44\xFC\x8E\x62\x9A\x01\x45\xAF\x56\xA5'
CSP_HEADER_FORMAT = '<16sL'
CSP_HEADER_SIZE = calcsize(CSP_HEADER_FORMAT)
CSPFileHeader = namedtuple('CSPFileHeader', ['magic', 'flag'])
CSP_MAX_KEY_VERSION = 0x41
CSP_KEY_TYPE = ['Do Not Use', 'Release', 'Development', 'Rollover'] # or `Unknown`

# enum of csp layout
CSP_LAYOUT_SIGNATURE_GUID = 0
CSP_LAYOUT_FLAG = 1
CSP_LAYOUT_FILENAME = 2
CSP_LAYOUT_PASSWORD_LEN = 3
CSP_LAYOUT_APPL_NAME_LEN = 4
CSP_LAYOUT_APPL_LEN = 5
CSP_LAYOUT_METADATA_LEN = 6
CSP_LAYOUT_PASSWORD = 7
CSP_LAYOUT_APPL_NAME = 8
CSP_LAYOUT_APPL = 9
CSP_LAYOUT_METADATA = 10
CSP_LAYOUT_SIGNATURE_ENVELOPE = 11
CSP_LAYOUT_METADATA_SIGN_LEN = 12
CSP_LAYOUT_METADATA_SIGN = 13

CSPv1_HEADER_FORMAT = '<256sLLLLQ'
CSPv1_HEADER_SIZE = calcsize(CSPv1_HEADER_FORMAT)
CSPv1Header = namedtuple('CSPv1Header', ['filename', 'password_len', 'appl_name_len', 'metadata_len', 'sign_len', 'appl_len'])


class Layout(object):
	def __init__(self, fd, type, size, filename=None):
		super(Layout, self).__init__()
		self.fd = fd
		self.offset = fd.tell()
		self.type = type
		self.size = size
		self.filename = filename
		fd.seek(self.offset + self.size)

	@property
	def value(self):
		self.fd.seek(self.offset)
		return str2bytes(self.fd.read(self.size))

	def __repr__(self):
		return '<{}(type: {}, offset: {}, size: {}, filename: {})>'.format(
			self.__class__.__name__, self.type, self.offset, self.size, self.filename)


class CSPFile(object):
	chunksize = 0x10000

	def __init__(self, fd, mod):
		super(CSPFile, self).__init__()
		self.fd = fd
		self.csp_header = CSPFileHeader._make(unpack(CSP_HEADER_FORMAT, str2bytes(fd.read(CSP_HEADER_SIZE))))
		assert self.csp_header.magic == CSP_SIGNATURE_GUID

		self.key_type = self.csp_header.flag & 0x03
		self.key_version = ((self.csp_header.flag >> 2) & 0x3F)
		self.key_version_c = bytes(str(self.key_version), 'ascii').hex()
		self.version = ((self.csp_header.flag >> 8) & 0xFF)
		self.verbose = mod.config.verbose
		self.verbose_offset = mod.HEADER_FORMAT.strip('\n') % ('', '', '')
		getattr(self, 'load_v{:d}'.format(self.version), self.unsupported_csp)()

	# CSP v1 methods

	def load_v1(self):
		v1_header = CSPv1Header._make(unpack(CSPv1_HEADER_FORMAT, str2bytes(self.fd.read(CSPv1_HEADER_SIZE))))
		self.size = CSP_HEADER_SIZE + CSPv1_HEADER_SIZE + v1_header.password_len + \
			v1_header.appl_name_len + v1_header.metadata_len + v1_header.sign_len + \
			v1_header.appl_len + v1_header.sign_len

		self.layout = [
			Layout(self.fd, CSP_LAYOUT_PASSWORD, v1_header.password_len),
			Layout(self.fd, CSP_LAYOUT_APPL_NAME, v1_header.appl_name_len),
			Layout(self.fd, CSP_LAYOUT_METADATA, v1_header.metadata_len),
			Layout(self.fd, CSP_LAYOUT_METADATA_SIGN, v1_header.sign_len),
			Layout(self.fd, CSP_LAYOUT_APPL, v1_header.appl_len),
			Layout(self.fd, CSP_LAYOUT_SIGNATURE_ENVELOPE, v1_header.sign_len)
		]

		filename = v1_header.filename.strip(b'\x00')
		metadata_filename, appl_filename = next(filter(lambda l: l.type == CSP_LAYOUT_APPL_NAME, self.layout)).value.split()

		layout_filenames = {
			CSP_LAYOUT_PASSWORD: filename + b'.pwd',
			CSP_LAYOUT_METADATA: metadata_filename,
			CSP_LAYOUT_METADATA_SIGN: metadata_filename + b'.sig',
			CSP_LAYOUT_APPL: appl_filename, # b'.enc'
			CSP_LAYOUT_SIGNATURE_ENVELOPE: filename + b'.sig'
		}

		for l in self.layout:
			l.filename = layout_filenames.get(l.type, None)

	def decrypt_v1(self, chunk):
		# -- snip --
		return chunk

	def description_v1(self):
		metadata = json.loads(next(filter(lambda l: l.type == CSP_LAYOUT_METADATA, self.layout)).value)
		csp_type = metadata.get('CSP_TYPE', '')
		msg = ''
		if csp_type:
			msg += '\n{pad}Type: {}'.format(csp_type.title(), pad='\x00' * len(self.verbose_offset))
			if csp_type == 'APPLICATION':
				msg += ' ({} v{}, build date: {})'.format(
					metadata.get('APPLICATION_NAME', '').title(),
					metadata.get('APPLICATION_VERSION', ''),
					metadata.get('APPLICATION_BUILD_DATE', ''))
		return msg

	def extract_v1(self):
		for l in self.layout:
			if l.filename is not None:
				self.fd.seek(l.offset)
				out_filename = unique_file_name(l.filename.decode())
				with open(out_filename, 'w+b') as out_fd:
					n, cz = 0, self.chunksize
					while n < l.size:
						n += cz
						if n > l.size:
							cz -= n - l.size
						chunk = str2bytes(self.fd.read(cz))
						if l.type == CSP_LAYOUT_APPL:
							chunk = self.decrypt_v1(chunk)
						out_fd.write(chunk)

	# base methods

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

	@property
	def description(self):
		return '{} v{:d}, flag: 0x{:08X}, key type: {} [{:d}], key ver: 0x{:02X}, size: {:d}'.format(
			SIG_DESCRIPTION, self.version, self.csp_header.flag, 
			CSP_KEY_TYPE[self.key_type], self.key_type, self.key_version, self.size) + \
			(getattr(self, 'description_v{:d}'.format(self.version), lambda: '')() if self.verbose else '')

	def unsupported_csp(self):
		raise Exception('Unsupported CSP version {}'.format(self.version))

	def extract(self):
		return getattr(self, 'extract_v{:d}'.format(self.version), self.unsupported_csp)()

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
		return '<{}({})>'.format(self.__class__.__name__, self.description)


class CiscoCSPFile(Plugin):
	MODULES = ['Signature']

	def init(self):
		if self.module.extractor.enabled:
			self.module.extractor.add_rule(txtrule=False, regex='^{}'.format(SIG_DESCRIPTION.lower()), extension='csp', cmd=self.extractor)

	def extractor(self, fname):
		with CSPFile(self.module.config.open_file(abspath(fname)), self.module) as csp:
			return csp.extract()

	def scan(self, result):
		if result.valid and result.description.startswith(SIG_DESCRIPTION) and isinstance(result, SignatureResult):
			fd = self.module.config.open_file(abspath(result.file.path), offset=result.offset)
			with CSPFile(fd, self.module) as csp:
				result.description = csp.description
				result.jump = result.offset + csp.size

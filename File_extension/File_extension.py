import argparse
import json
import sys
import os
import pyaes


def prepare(path, dest):
	""" Extend file and prepend dictionary to it """
	with open(path, 'rb') as f:
		data = f.read()

	prepare_file(data, dest)


def prepare_file(data, path):
	""" Add dict to data and extend those with zeroes """
	dic = create_dict()
	ext_file = extend_file_data(data)

	with open(path, 'wb') as f:
		f.write(dic)
		f.write(ext_file)


def create_dict():
	""" Create dictionary table """
	return bytes(map(lambda n: n // 16 if n % 16 == 0 else 0, range(4096)))


def extend_file_data(data):
	""" Extend file data """
	ext_data = []
	for b in data:
		ext_data.extend([b] + [0] * 15)
	return bytes(ext_data)


def encode(path, dest):
	""" Encode file with AES ECB """
	key = os.urandom(16)
	aes = pyaes.AESModeOfOperationECB(key)

	with open(path, 'rb') as f:
		data = f.read()

	if len(data) % 16 != 0:
		raise IOError("File to encode must have length of 16")

	enc = b''
	for i in range(0, len(data), 16):
		enc += aes.encrypt(data[i:i+16])

	with open(dest, 'wb')as f:
		f.write(enc)


def translate(path, dest):
	""" Exctract dictionary to separate file """
	dict_bytes = extract_dict(path)
	write_dict(dict_bytes, dest)


def extract_dict(path):
	""" Read dictionary from file """
	with open(path, 'rb') as f:
		dict_bytes = f.read(4096)
	return dict_bytes


def write_dict(dict_bytes, dest):
	""" Write dictionary data to seperate file """
	dic = transform_dict(dict_bytes)
	with open(dest, 'wt') as f:
		for i in range(256):
			f.write(f'{i}->{json.dumps(dic[i])}\n')


def transform_dict(dict_bytes):
	""" Convert dictionary bytes to list """
	dic = []
	for i in range(256):
		val = list(dict_bytes[i*16:(i+1)*16])
		dic.append(val)
	return dic


def decode(path, dest):
	""" Decode file that was extended and then encoded with AES ECB """
	with open(path, 'rb') as f:
		data = f.read()
	table = get_table(data[:4096])
	dec = decode_data(data[4096:], table)
	with open(dest, 'wb') as f:
		f.write(dec)


def get_table(bts):
	""" Return table dictionary """
	table = dict()
	for i in range(256):
		key = bts[i*16:(i+1)*16]
		table[key] = i
	return table


def decode_data(data, table):
	""" Decode data with precalculated table """
	dec = []
	for i in range(0, len(data), 16):
		dec.append(table[data[i:i+16]])
	return bytes(dec)


def main():
	parser = argparse.ArgumentParser(description='This application process your files to defend those from AES encoding.')

	subparsers = parser.add_subparsers(dest="command")

	prepare_parser = subparsers.add_parser('prepare', help='Extend file to defend it from AES encoding')
	prepare_parser.add_argument('-i', '--input', action='store', type=str, help='Origin file path', metavar='path', required=True)
	prepare_parser.add_argument('-o', '--output', action="store", type=str, help='Extended file path', metavar='path', default='extended.txt')

	prepare_parser = subparsers.add_parser('encode', help='Encode file with AES ECB')
	prepare_parser.add_argument('-i', '--input', action='store', type=str, help='File to encode', metavar='path', required=True)
	prepare_parser.add_argument('-o', '--output', action="store", type=str, help='Decoded file', metavar='path', default='encoded.txt')

	translate_parser = subparsers.add_parser('translate', help='Extract dictionary table from encoded file')
	translate_parser.add_argument('-i', '--input', action='store', type=str, help='Encoded file path', metavar='path', required=True)
	translate_parser.add_argument('-o', '--output', action='store', type=str, help='Dictionary file path', metavar='path', default='dictionary.txt')

	decode_parser = subparsers.add_parser('decode', help='Decode encoded file')
	decode_parser.add_argument('-i', '--input', action='store', type=str, help='Encoded file path', metavar='path', default='extended.txt')
	decode_parser.add_argument('-o', '--output', action='store', type=str, help='Decoded file path', metavar='path', default='decoded.txt')

	args = parser.parse_args(sys.argv[1:])

	try:
		if args.command == 'prepare':
			prepare(args.input, args.output)
		elif args.command == 'encode':
			encode(args.input, args.output)
		elif args.command == 'translate':
			translate(args.input, args.output)
		elif args.command == 'decode':
			decode(args.input, args.output)
		else:
			parser.print_help()
	except IOError as error:
		print(error)


if __name__ == '__main__':
	main()
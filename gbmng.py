#!/usr/bin/python
# -*- codeing: utf-8 -*-
# Author: XYlearn
# Email: xylearn@qq.com

import paramiko
import socket
import hashlib
import os
import argparse
import cmd
import re
import getpass
import sqlite3
import string
import time

VERBOSE_SEVERE = 1
VERBOSE_INFO = 2
VERBOSE_DEBUG = 3
VERBOSE_FAIL = -1
VERBOSE_SUCCESS = 0
VERBOSE = VERBOSE_INFO

try:
	input = raw_input
except NameError:
	pass


def verbose(msg, verbose_level=VERBOSE_INFO):
	'''print msg according to verbose_level

	Args:
		msg (str): message to show
		verbose_level (int): contain the verbose level or type information
	'''
	if verbose_level == VERBOSE_FAIL:
		print("[-] " + msg)
	elif verbose_level == VERBOSE_SUCCESS:
		print("[+] " + msg)
	elif verbose_level <= VERBOSE:
		print(msg)


class BinVersions:
	"""version data of binary on a gamebox"""
	def __init__(self, base_name):
		self.base_name = base_name
		self.versions = []

	def add_version(self, idx, hash_id, create_time):
		version = {}
		version["idx"] = idx
		version["hash"] = hash_id
		version["time"] = create_time
		self.versions.append(version)

	def delete_version(self):
		pass


class SSHConnection:
	"""ssh connection"""

	def __init__(self, host, username='', password='', port=22, use_key=False):
		'''create SSHConnection and set up the connection

		Args:
			host (str): host of gamebox
			username (str): username to connect as
			password (str): password for login or a rsa_key file
			port (int): connect port
			use_key (boolean): whether the password stands for rsa_key
		'''
		ssh = paramiko.SSHClient()
		ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
		if not use_key:
			ssh.connect(host, port , username, password)
		else:
			ssh.connect(host, port ,username, key_filename=password)
		self.ssh = ssh
		self.sftp = None

	def exec_command(self, cmd):
		stdin, stdout, stderr = self.ssh.exec_command(cmd)
		pipe = CommandPipe(stdin, stdout, stderr)
		return pipe

	def get_sftp(self):
		if not self.sftp:
			self.sftp = self.ssh.open_sftp()
		return self.sftp


class CommandPipe:
	"""pipe of command execution"""
	def __init__(self, stdin, stdout, stderr):
		self.stdin = stdin
		self.stdout = stdout
		self.stderr = stderr

	def send(self, s):
		self.stdin.write(s)

	def recv(self, err=False):
		if not err:
			return self.stdout.read()
		else:
			return self.stderr.read()


class GameBox:
	"""basic information of gamebox"""
	def __init__(self, name, host, port):
		self.name = name
		self.host = host
		self.port = port

	def __str__(self):
		return "%s (%s:%d)" % (self.name, self.host, self.port)


class Session(dict):
	"""session with context"""
	gbhome = os.path.join(os.getcwd(), ".gbmng")
	sdb_path = os.path.join(gbhome, ".gbs")
	def __init__(self):
		dict.__init__(self)
		self['host'] = '127.0.0.1'
		self['user'] = 'root'
		self['password'] = ''
		self['use_key'] = False
		self['port'] = 22
		self.__ssh = None
		try:
			# create table if not exists
			with sqlite3.connect(Session.sdb_path) as conn:
				cursor = conn.cursor()
				tables = map(lambda x:x[0], cursor.execute(
					"SELECT name FROM sqlite_master WHERE type='table' ORDER BY name;").fetchall())
				if 'gameboxes' not in tables:
					cursor.execute("CREATE TABLE gameboxes(name text, obj text);")
				conn.commit()
		except sqlite3.Error:
			verbose("Unknown error when creating table")

	def set_ssh(self, ssh):
		self.__ssh = ssh

	def get_ssh(self):
		return self.__ssh

	def get_configs(self):
		res = []
		for attr in self.keys():
			if attr.startswith("_"):
				continue
			else:
				res.append(attr)
		return res

	def get_config(self, config):
		if config == "conn":
			return self.__ssh != None
		elif self.has_key(config):
			return self[config]
		else:
			return None

	def show(self, keys=[]):
		if len(keys) == 0:
			verbose("[host]\t:%s" % repr(self.get_config('host')), VERBOSE_SEVERE)
			verbose("[user]\t:%s" % repr(self.get_config('user')), VERBOSE_SEVERE)
			verbose("[conn]\t:%s" % repr(self.get_config('conn')), VERBOSE_SEVERE)
		else:
			fill_count = max(map(lambda x:len(x), keys))
			for key in keys:
				if key != "conn" and not self.has_key(key):
					verbose("Unknow configuration key %s" % repr(key), VERBOSE_FAIL)
					return
			for key in keys:
				verbose("[%s]\t:%s" % (key.center(fill_count), repr(self.get_config(key))), VERBOSE_SEVERE)

	def save(self, name):
		'''save session to database

		Args:
			name (str): name to save as

		Return:
			bool: whether the database is updated
		'''
		# check if name is valid
		if not Session.__check_name(name):
			verbose("Invalid session name %s" % repr(name))
			return False
		
		obj = str(self)
		
		try:
			with sqlite3.connect(Session.sdb_path) as conn:
				# check existence
				cursor = conn.cursor()
				existed = len(cursor.execute("SELECT name from gameboxes WHERE name='%s'" % name).fetchall()) != 0
				if existed:
					overwrite_str = input("Session %s already exists. overwrite?(Y/n) " % name)
					if overwrite_str.lower() == 'n':
						return False
					else:
						cursor.execute("UPDATE gameboxes SET obj=%s WHERE name=%s" % (repr(obj), repr(name)))
				else:
					cursor.execute("INSERT INTO gameboxes VALUES(%s, %s)" % (repr(name), repr(obj)))
				conn.commit()
				return True
		except sqlite3.Error as e:
			verbose(str(e), VERBOSE_FAIL)
			return False

	@classmethod
	def get_gblist(cls):
		'''list gameboxes saved in database'''
		with sqlite3.connect(Session.sdb_path) as conn:
			cursor = conn.cursor()
			names = map(lambda x:x[0], cursor.execute("SELECT name from gameboxes").fetchall())
		gblist = []
		for name in names:
			session = Session.open_session(name)
			gblist.append(GameBox(name, session.get_config("host"), session.get_config("port")))
		return gblist

	@classmethod
	def __check_name(cls, name):
		for c in name:
			if c not in string.ascii_letters:
				return False
		return True

	@classmethod
	def open_session(cls, name):
		'''get stored session with name in database

		Args:
			name (str): name of session in database

		Raises:
			sqlite3.Error : raise when sqlite operation failed

		'''
		if not Session.__check_name(name):
			verbose("Invalid session name %s" % repr(name), VERBOSE_FAIL)
			return None

		try:
			with sqlite3.connect(Session.sdb_path) as conn:
				cursor = conn.cursor()

				obj = cursor.execute("SELECT obj FROM gameboxes WHERE name='%s'" % name).fetchone()[0]
		except sqlite3.Error as e:
			verbose(str(e), VERBOSE_FAIL)

		try:
			session = Session()
			configs = eval(obj)
			for key in configs:
				session[key] = configs[key]
			return session
		except Exception as e:
			verbose(str(e), VERBOSE_FAIL)
			return None
		
	@classmethod
	def set_sdb(cls, sdb_path):
		cls.sdb_path = sdb_path


class GBCli(cmd.Cmd):
	"""CLI of GameBox Manager"""
	def __init__(self, session=None):
		cmd.Cmd.__init__(self)
		if session:
			self.session = session
		else:
			self.session = Session()
		self.welcomed = False

	def cmdloop(self, intro=None):
		while True:
			try:
				cmd.Cmd.cmdloop(self, intro="")
				break
			except KeyboardInterrupt:
				print("^C")
				continue

	def preloop(self):
		if not self.welcomed:
			welcome()
		self.welcomed = True

	def postcmd(self, stop, line):
		return cmd.Cmd.postcmd(self, stop, line)

	def help_config(self):
		print(
'''config [key] (value)
	set session key to value. if value not specified, input from keyboard.
config show (key)
	show configures. if no key specified, will show basic information''')

	def help_upload(self):
		print(
'''upload [src] [dst]
	upload local file [src] to [dst] on remote gamebox''')

	def help_backup(self):
		print(
'''backup [path]
	backup file. [path] is abs path or relative path to home.''')

	def help_session(self):
		print(
'''session save [name]
	save current session to database
session load [name]
	load session from database
session list
	show basic information of sessions in database''')

	def help_connect(self):
		print('''connect to remote gamebox in current session''')

	def do_config(self, args):
		argv = _parseline(args)
		if len(argv) == 0:
			self.help_config()
			return
		elif argv[0] == "show":
			self.session.show(argv[1:])
			return
		elif argv[0] not in self.session.get_configs():
			verbose("Unknow configuration key %s" % repr(argv[0]), VERBOSE_FAIL)
			return
		elif len(argv) == 1:
			if argv[0] == "password":
				self.session[argv[0]] = getpass.getpass(argv[0] + " : ")
			else:
				self.session[argv[0]] = input(argv[0] + " : ")
		elif len(argv) != 2:
			verbose("Invalid argument number", VERBOSE_FAIL)
		else:
			try:
				key = argv[0]
				value = type(self.session[key])(argv[1])
				self.session[key] = value
			except ValueError:
				verbose("Invalid argument type", VERBOSE_FAIL)

	def do_upload(self, args):
		if not self.session.get_config("conn"):
			verbose("Not connected", VERBOSE_FAIL)
		argv = _parseline(args)
		try:
			src = argv[0]
			dst = argv[1]
		except IndexError:
			verbose("Invalid argument number", VERBOSE_FAIL)
			return
		if not access_file_local(src):
			verbose("Local file %s not exist" % repr(src), VERBOSE_FAIL)
			return
		upload_patch(self.session.get_ssh(), src, dst, backup=True)

	def do_backup(self, args):
		if not self.session.get_config("conn"):
			verbose("Not connected", VERBOSE_FAIL)
		argv = _parseline(args)
		try:
			pathname = argv[0].strip()
		except IndexError:
			verbose("Invalid argument number", VERBOSE_FAIL)
			return
		if not access_file_remote(self.session.get_ssh(), pathname):
			verbose("Remote file %s not exists" % pathname, VERBOSE_FAIL)
			return
		else:
			backup_remote(self.session.get_ssh(), pathname)
		
	def do_session(self, args):
		argv = _parseline(args)
		if argv[0] == "save":
			if len(argv) != 2:
				verbose("Invalid argument number")
				return
			self.session.save(argv[1])
		elif argv[0] == "load":
			if len(argv) != 2:
				verbose("Invalid argument number")
				return
			session = Session.open_session(argv[1])
			if session:
				self.session = session
		elif argv[0] == "list":
			gblist = Session.get_gblist()
			for gb in gblist:
				print gb
		else:
			verbose("Unknow command %s for session" % argv[0], VERBOSE_FAIL)

	def do_connect(self, args):
		session = self.session
		try:
			ssh = SSHConnection(session['host'], session['user'], password=session['password'], 
				port=session['port'], use_key=session['use_key'])
		except Exception:
			verbose("conncetion fail", VERBOSE_FAIL)
			return
		self.session.set_ssh(ssh)

	def do_exit(self, args):
		exit()


def _parseline(line):
	res = re.split(r"\s*", line.strip())
	try:
		while True:
			res.remove("")
	except Exception:
		return res


def remote_path(pathname):
	if not os.path.isabs(pathname):
		return "~/" + pathname.strip()
	else:
		return pathname.strip()


def get_md5_local(filepath):
	with open(filepath, "r") as f:
		cont = f.read()
	md5 = hashlib.md5(cont).hexdigest()
	return md5


def get_md5_remote(ssh, filepath, md5_cmd="md5sum"):
	# check relative path
	filepath = filepath.strip()
	pipe = ssh.exec_command(md5_cmd + " " + filepath)
	md5 = pipe.recv().split(' ')[0].strip()
	return md5


def access_file_local(filepath):
	return os.path.exists(filepath)


def access_file_remote(ssh, filepath):
	filepath = remote_path(filepath)
	# use ls to check if file exists
	pipe = ssh.exec_command("ls %s" % filepath)
	if pipe.recv(True):
		return False
	return True


def backup_remote(ssh, pathname):
	'''backup binary on remote gamebox
	'''
	if not access_file_remote(ssh, pathname):
		verbose("File %s doesn't exist. Backup nothing" % pathname, VERBOSE_FAIL)
		return False
	else:
		backup_id = 1
		backup_name = pathname.strip() + ".bak%d" % backup_id
		while access_file_remote(ssh, backup_name):
			backup_id += 1
			backup_name = pathname.strip() + ".bak%d" % backup_id
		pipe = ssh.exec_command("cp %s %s" % (pathname, backup_name))
		res = pipe.recv(True)
		if res:
			verbose("Fail to backup: %s" % res.strip(), VERBOSE_FAIL)
			return False
		return True


def upload_patch(ssh, srcpath, dstpath, **kargs):
	if kargs.has_key("md5_cmd"):
		md5_cmd = kargs["md5_cmd"]
	else:
		# set md5sum as default md5 command
		md5_cmd = "md5sum"
	if kargs.has_key("backup"):
		backup = kargs["backup"]
	else:
		backup = True

	# check existance of srcpath
	if not access_file_local(srcpath):
		verbose("Local File %s doesn't exists." % repr(srcpath), VERBOSE_FAIL)
		return False

	# check existance of dstpath
	if backup:
		existed = access_file_remote(ssh, dstpath)
		if existed:
			# create backup
			if not backup_remote(ssh, dstpath):
				return False

	# upload file
	sftp = ssh.get_sftp()
	sftp.put(srcpath, dstpath)
	if not access_file_remote(ssh, dstpath):
		verbose("Can't upload %s to %s" % (repr(srcpath), repr(dstpath)), VERBOSE_FAIL)
		return False

	# chmod
	pipe = ssh.exec_command("chmod +x %s" % dstpath)
	if pipe.recv(True):
		verbose("chmod fail", VERBOSE_FAIL)

	# check md5
	md5_src = get_md5_local(srcpath)
	md5_dst = get_md5_remote(ssh, dstpath, md5_cmd=md5_cmd)
	verbose("[*] src MD5 %s %s" % (md5_src, srcpath))
	verbose("[*] dst MD5 %s %s" % (md5_dst, dstpath))
	if md5_src != md5_dst:
		verbose("[!] MD5 not equal. Please upload again.")
		return False
	else:
		verbose("Upload success!", VERBOSE_SUCCESS)
		return True


def __parse_args():
	parser = argparse.ArgumentParser(description = "A patch manager")
	parser.add_argument("-H", "--host", default="127.0.0.1", type=str, help="host of dest server")
	parser.add_argument("-u", "--user", default="root", type=str, help="user to login as")
	parser.add_argument("-p", "--password", default='', type=str, help="ssh password. if user_")
	parser.add_argument("-k", "--use_key", default=False, help="if specified password represents key filename", action='store_true')
	parser.add_argument("-P", "--port", default=22, type=int, help="ssh port")
	parser.add_argument("-s", "--session", default="", help="session to open")
	parser.add_argument("-f", "--file", default=".gbs", help="session database")
	return parser.parse_args()


def welcome():
	print(r'''   ___                       ___
  / _ \__ _ _ __ ___   ___  / __\ _____  __
 / /_\/ _` | '_ ` _ \ / _ \/__\/// _ \ \/ /
/ /_\\ (_| | | | | | |  __/ \/  \ (_) >  <
\____/\__,_|_| |_| |_|\___\_____/\___/_/\_\


  /\/\   __ _ _ __   __ _  __ _  ___ _ __
 /    \ / _` | '_ \ / _` |/ _` |/ _ \ '__|
/ /\/\ \ (_| | | | | (_| | (_| |  __/ |
\/    \/\__,_|_| |_|\__,_|\__, |\___|_|
                          |___/
''')


def environ_init(path="."):
	gbhome = Session.gbhome
	path = os.path.abspath(path)
	if not path:
		verbose("Invalid path %s" % repr(path), VERBOSE_FAIL)
		exit()
	if not access_file_local(path):
		verbose("Path %s not exists" % repr(path), VERBOSE_FAIL)
		exit()
	if access_file_local(gbhome):
		if os.path.isdir(gbhome):
			return
		else:
			verbose("%s is not a dir" % repr(gbhome))
			exit()
	else:
		os.mkdir(gbhome)
		

def main():
	environ_init()
	args = __parse_args()
	if args.file:
		Session.sdb_path = args.file
	if args.session:
		session = Session.open_session(args.session)
		if session:
			verbose("Finish load session", VERBOSE_SUCCESS)
	else:
		session = Session()
		session['host'] = args.host
		session['port'] = args.port
		session['user'] = args.user
		session['password'] = args.password
		session['use_key'] = args.use_key

	cli = GBCli(session)
	cli.cmdloop()


if __name__ == "__main__":
	main()
	
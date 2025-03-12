#This code changes the password.

import os
import time
import pickle
from cryptography.fernet import Fernet

from manager import generate_key, check_master_password, DATA_FILE_PATH, fetch_list, store_list
from getpass import getpass
from version_check import version_check #Contains dependency versions to be strictly enforced

def backup_old_data_file(loc:str, extension:str=None):
	if loc not in os.listdir():
		os.mkdir(loc)
	os.system("copy data_file " + loc)
	if extension != None:
		os.rename(loc + "/data_file", loc + "/data_file_" + extension)

def backup_old_master_password_hash(loc:str, extension:str=None):
	if loc not in os.listdir():
		os.mkdir(loc)
	os.system("copy master_password_hash " + loc)
	if extension != None:
		os.rename(loc + "/master_password_hash", loc + "/master_password_hash_" + extension)

def create_master_password_hash(masterPassword:str, salt:str="salt"):
	"""
	Does not backup.
	Caller's responsiblity to make backups if wanted.
	"""
	from cryptography.hazmat.primitives import hashes
	digest = hashes.Hash(hashes.SHA256())
	hash_input = (masterPassword + salt).encode()
	digest.update(hash_input)
	with open("master_password_hash", "wb") as f1:
		f1.write(digest.finalize())

def re_encrypt(
				fernDec,
				fernEnc,
				):
	"""
	Does not backup.
	Caller's responsiblity to make backups if wanted.
	"""
	dataList = fetch_list()

	for i in range(len(dataList)):
		for j in range(len(dataList[i])):
			dataList[i][j] = fernEnc.encrypt(fernDec.decrypt(dataList[i][j]))

	store_list(dataList)

def main():

	version_check()#Makes sure the program is being run with enforced versions

	oldPassword = getpass(prompt="Old Password: ")
	if not check_master_password(oldPassword):
		print("Wrong password")
		exit()

	newPassword = input("BE ALONE !!! and input new password: ")
	if len(newPassword) < 16:
		if input("WARNING: new password < 16 chars. Continue? (y/n)") != "y":
			exit() 

	fernDec = Fernet(generate_key(oldPassword))
	fernEnc = Fernet(generate_key(newPassword))

	loc = "old_file_backups"
	extension = time.strftime("%Y_%m_%d_%H_%M_%S")
	backup_old_master_password_hash(loc, extension)
	print("Backed up hash with extension " + extension)
	backup_old_data_file(loc, extension)
	print("Backed up data_file with extension " + extension)

	create_master_password_hash(newPassword)
	print("New hash created.")
	re_encrypt(fernDec=fernDec, fernEnc=fernEnc)
	print("New encrypted data_file created.")

if __name__=="__main__":
	main()

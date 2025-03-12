#This code creates decoys.

from os import mkdir, listdir
import pickle
from cryptography.fernet import Fernet

from manager import generate_key, check_master_password, fetch_list
from getpass import getpass
from version_check import version_check #Contains dependency versions to be strictly enforced

def create_decoy(
				source, #Relative path beginning with ./
				dest, #Relative path beginning with ./
				decryptKey,
				):
	"""
	Ensuring source and dest exist is responsibility of caller.
	However, breaking that should not cause any problems.
	"""

	#Get our crypto stuff
	fernDec = Fernet(decryptKey)
	fernEnc = Fernet(Fernet.generate_key()) #So this is a "lock it up and throw away the key" type of thing.

	dataList = fetch_list()

	for i in range(len(dataList)):
		for j in range(len(dataList[i])):
			dataList[i][j] = fernEnc.encrypt(fernDec.decrypt(dataList[i][j]))

	with open(dest + "/" + source[2:], "wb") as f2: #Not importing and using store_list bc this is different.
		pickle.dump(dataList, f2)

def main():

	version_check()#Makes sure the program is being run with enforced versions

	password = getpass()
	if not check_master_password(password):
		print("Wrong password")
		exit()

	decryptKey = generate_key(password)

	source = "./data_file"
	dest = "./data_decoys"
	if dest.replace("./", "") not in listdir():
		mkdir(dest)
	create_decoy(source, dest, decryptKey)

if __name__=="__main__":
	main()

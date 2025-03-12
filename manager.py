#PM2

"""
Archicture of data:
Python list of lists. Each inside list is an entry with the format:
[0] = title/name
[1] = tags
[2] = association 1
[3] = association 2
...
[n] = association n-1
"""

import pickle
import cryptography
from cryptography.fernet import Fernet
from getpass import getpass
from version_check import version_check #Contains dependency versions to be strictly enforced

DATA_FILE_PATH = r".\data_file"

DELETION_MARKER = "delete!@#" #Put in title to mark for deletion

def show(string:bytes, fernet:Fernet):
	"""Terse way to decrypt"""
	return fernet.decrypt(string).decode()

def hide(string:str, fernet:Fernet):
	"""Terse way to encrypt"""
	return fernet.encrypt(string.encode())

def generate_key(masterPassword):
	while len(masterPassword) < 43:#for some reason these keys are 44
		masterPassword += masterPassword
	return (masterPassword[0:43] + "=").encode()#for a total of 44

def check_master_password(masterPassword, salt="salt"):
	"""
	Tells you  whether you are using the right password.
	Important bc the AES key is based on it.
	"""
	from cryptography.hazmat.primitives import hashes
	digest = hashes.Hash(hashes.SHA256())
	hashInput = (masterPassword + salt).encode()
	digest.update(hashInput)
	with open("master_password_hash", "rb") as f1:
		return digest.finalize() == f1.read()

def fetch_list(path:str=DATA_FILE_PATH):
	"""Unpickles the encrypted data"""
	try:
		with open(path, "rb") as dataFile:
			dataList = pickle.load(dataFile)
	except FileNotFoundError:
		print(path + " not found." + \
			" If you continue a new file will be made.")
		if (input("Continue? (y/n)") != "y"):
			exit()
		else:
			dataList = []
	except EOFError as e: #This should most likely mean no data in file
		print("Warning: " + str(e))
		if (input("Continue? (y/n)") != "y"):
			exit()
		else:
			dataList = []
	return dataList

def store_list(pickleList:list, path:str=DATA_FILE_PATH):
	"""Pickles the encrypted data"""
	with open(path, "wb") as dataFile:
		pickle.dump(pickleList, dataFile)
	print("Saved changes.")

def display_edit(query:str, f:Fernet):
	masterList = fetch_list()
	displayList = []

	#Collect
	for entry in masterList:
		#check if query in title or tags
		if (query.lower() in show(entry[0], f).lower()) or \
			(query.lower() in show(entry[1], f).lower()):
			displayList.append(entry)

	#Show / Edit
	while True:
		index = 0
		print()#newline
		for entry in displayList:
			print(str(index + 1) + ". " + \
				show(entry[0], f) + \
				" "*6 + "Tags: " + \
				show(entry[1], f))
			index += 1
		userChoice = input("\nChoose an entry num," + \
			" b/q to back out, enter to exit: ")
		if userChoice == 'q' or userChoice == 'b':
			break
		elif userChoice == "": #user just hit enter
			exit()
		try:
			assert(int(userChoice) >= 1)
			entryChoice = displayList[int(userChoice) - 1]
		except (ValueError, AssertionError):
			print("Bad input. Breaking.")
			break
		except IndexError:
			print("Out of range. Breaking.")
			break

		while True:
			index = 0
			print()#newline
			for string in entryChoice:
				print(
					#separate associations for easy viewability
					(("\n") if index == 2 else ("")) + \
					#extra indent for associations (index >= 2)
					((" "*7) if index >= 2 else ("")) + \
					str(index + 1) + ". " + \
					show(string, f))
				index += 1
			editChoice = input(\
				"\nSelect a number to edit,"+ \
				" b/q to back out, enter to exit: ")
			if editChoice == '': #user just hit enter
				exit()
			elif editChoice == 'b' or editChoice == 'q':
				break
			try:
				assert(int(editChoice) >= 1)
				editNum = int(editChoice) - 1
				if editNum >= len(entryChoice):
					entryChoice.append(hide(input("new association: "), f))
				else:
					entryChoice[editNum] = hide(\
						input("\nEnter new string: "), f)
				store_list(masterList)
			except (ValueError, AssertionError):
				print("Bad input. Breaking.")
				break
			except IndexError:
				print("Out of range. Breaking.")
				break

def add_entry(f:Fernet):
	masterList = fetch_list()

	#Create
	entry = []
	entry.append(hide(input("Title: "), f))
	entry.append(hide(input("Tags: "), f))
	while True:
		additionalInput = input("new association: ")
		if additionalInput == "done.":
			break
		else:
			entry.append(hide(additionalInput, f))

	#Store
	masterList.append(entry)
	store_list(masterList)

def remove_entries(f:Fernet, marker:str=DELETION_MARKER):
	"""
	Removes entries that have been marked for deletion.
	Done this way instead of easily by option to avoid typos that could
	accidentally delete an entry that should have been kept.
	Mark in title.
	"""
	masterList = fetch_list()
	deleteList = []

	for entry in masterList:
		if marker in show(entry[0], f):
			deleteList.append(entry)

	delCount = 0
	for entry in deleteList:
		masterList.remove(entry)
		delCount += 1

	store_list(masterList)
	print("Finished. Deleted count: " + str(delCount))

def main():

	version_check()#Makes sure the program is being run with enforced versions

	#Master password check stops you from going forward with wrong password.
	#Important bc the AES key is based on it.
	masterPassword = getpass()
	if not check_master_password(masterPassword):
		print("Wrong password for cryptography.")
		exit()

	#Generate key for AES
	key = generate_key(masterPassword)

	#Get the fernet
	fernet = Fernet(key)

	while True:
		print("\n(1) display/edit entries" + \
			"\n(2) add entries" + \
			"\n(3) remove entries marked for deletion" + \
			"\n(q) quit")
		mode = input("\nSelect option: ")

		if mode == 'q':
			break
		if mode == '1':
			display_edit(input("\nSubstring in place? (Enter = all): "),\
				fernet)
		elif mode == '2':
			add_entry(fernet)
		elif mode == '3':
			remove_entries(fernet)
		else:
			print("Unrecognized input for mode choice.")

if __name__ == "__main__":
	main()

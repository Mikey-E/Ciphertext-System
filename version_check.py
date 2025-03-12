def version_check():
	"""Dependency check"""
	import sys
	import pickle
	import cryptography

	#Package versions to be strictly enforced
	assert(pickle.format_version == "4.0")#(why format version? pickle is a builtin; it has no __version__)
	assert(cryptography.__version__ == "39.0.0")

	#Python version to be strictly enforced
	assert(sys.version_info.major == 3)
	assert(sys.version_info.minor == 11)
#	assert(sys.version_info.micro == 1)#not concerned about micro

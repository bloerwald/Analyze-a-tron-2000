.PHONY: default
default: wowdbdefs-update

DBD_CODE_PATH = $(PWD)/WoWDBDefs/code/Python3
PYTHON3 = PYTHONPATH=$(DBD_CODE_PATH) python3

WOW_BUILD = 9.0.1.34972

WoWDBDefs:
	git clone "https://github.com/wowdev/WoWDBDefs.git"

.PHONY: wowdbdefs-update
wowdbdefs-update: WoWDBDefs
	: cd WoWDBDefs/ && git pull

dbd_based_structs.h: wowdbdefs-update $(wildcard WoWDBDefs/definitions/*.dbd)
	: #	pip3 install --requirement $(DBD_CODE_PATH)/requirements.txt
	$(PYTHON3) dbd_based_structs.py \
	  --definitions $(PWD)/WoWDBDefs/definitions \
	  --build $(WOW_BUILD) > $@

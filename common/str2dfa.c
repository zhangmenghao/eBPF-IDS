/*************************************************************************
	> File Name: str2dfa.c
	> Author: Guanyu Li
	> Mail: dracula.register@gmail.com
	> Created Time: Mon 02 Dec 2019 02:17:40 PM CST
 ************************************************************************/

#include <stdio.h>
#include <Python.h>
#include "str2dfa.h"

int
str2dfa(char **pattern_list, int pattern_list_len, struct str2dfa_kv **result) {
	PyObject *pName, *pModule, *pFunc, *pArgs, *pReturn;
	int i_pattern, i_entry, n_entry;

	Py_Initialize();
	PyRun_SimpleString("import sys\n");
	PyRun_SimpleString("sys.path.append('common')\n");

	pName = PyString_FromString("str2dfa");
	/* Error checking of pName left out */

	pModule = PyImport_Import(pName);
	Py_DECREF(pName);

	if (pModule != NULL) {
		pFunc = PyObject_GetAttrString(pModule, "str2dfa");
		/* pFunc is a new reference */

		if (pFunc && PyCallable_Check(pFunc)) {
			pArgs = PyTuple_New(1);
			PyObject *pPatternList, *pPattern;
			pPatternList = PyList_New(0);
			if (!pPatternList) {
				Py_DECREF(pArgs);
				Py_DECREF(pModule);
				fprintf(stderr, "Cannot convert argument\n");
				return -1;
			}
			for (i_pattern = 0; i_pattern < pattern_list_len; i_pattern++) {
				pPattern = PyString_FromString(pattern_list[i_pattern]);
				if (!pPattern) {
					Py_DECREF(pArgs);
					Py_DECREF(pModule);
					fprintf(stderr, "Cannot convert argument\n");
					return -1;
				}
				PyList_Insert(pPatternList, i_pattern, pPattern);
			}
			PyTuple_SetItem(pArgs, 0, pPatternList);
			pReturn = PyObject_CallObject(pFunc, pArgs);
			Py_DECREF(pArgs);
			if (pReturn != NULL) {
				PyObject *pKey, *pValue, *pEntry;
				n_entry = PyList_Size(pReturn);
				struct str2dfa_kv *entries = (struct str2dfa_kv *)
					malloc(sizeof(struct str2dfa_kv) * n_entry);
				for (i_entry = 0; i_entry < n_entry; i_entry++) {
					pEntry = PyList_GetItem(pReturn, i_entry);
					pKey = PyTuple_GetItem(pEntry, 0);
					pValue = PyTuple_GetItem(pEntry, 1);
					entries[i_entry].key_state =
						PyInt_AsLong(PyTuple_GetItem(pKey, 0));
					entries[i_entry].key_unit =
						(PyString_AsString(PyTuple_GetItem(pKey, 1)))[0];
					entries[i_entry].value_state =
						PyInt_AsLong(PyTuple_GetItem(pValue, 0));
					entries[i_entry].value_flag =
						PyInt_AsLong(PyTuple_GetItem(pValue, 1));
				}
				*result = entries;
				Py_DECREF(pKey);
				Py_DECREF(pValue);
				Py_DECREF(pEntry);
			}
			else {
				Py_DECREF(pFunc);
				Py_DECREF(pModule);
				PyErr_Print();
				fprintf(stderr,"Call failed\n");
				return -1;
			}
		}
		else {
			if (PyErr_Occurred())
				PyErr_Print();
				fprintf(stderr, "Cannot find function \"str2dfa\"\n");
		}
	}
	else {
		PyErr_Print();
		fprintf(stderr, "Failed to load \"str2dfa\"\n");
		return -1;
	}
	Py_Finalize();
	return n_entry;
}

int
str2dfa_fromfile(const char *pattern_file, struct str2dfa_kv **result) {
	PyObject *pName, *pModule, *pFunc, *pArgs, *pReturn;
	int i_pattern, i_entry, n_entry;

	Py_Initialize();
	PyRun_SimpleString("import sys\n");
	PyRun_SimpleString("sys.path.append('common')\n");

	pName = PyString_FromString("str2dfa");
	/* Error checking of pName left out */

	pModule = PyImport_Import(pName);
	Py_DECREF(pName);

	if (pModule != NULL) {
		pFunc = PyObject_GetAttrString(pModule, "str2dfa");
		/* pFunc is a new reference */

		if (pFunc && PyCallable_Check(pFunc)) {
			pArgs = PyTuple_New(1);
			PyObject *pPatternList;
			pPatternList = PyString_FromString(pattern_file);
			if (!pPatternList) {
				Py_DECREF(pArgs);
				Py_DECREF(pModule);
				fprintf(stderr, "Cannot convert argument\n");
				return -1;
			}
			PyTuple_SetItem(pArgs, 0, pPatternList);
			pReturn = PyObject_CallObject(pFunc, pArgs);
			Py_DECREF(pArgs);
			if (pReturn != NULL) {
				PyObject *pKey, *pValue, *pEntry;
				n_entry = PyList_Size(pReturn);
				struct str2dfa_kv *entries = (struct str2dfa_kv *)
					malloc(sizeof(struct str2dfa_kv) * n_entry);
				for (i_entry = 0; i_entry < n_entry; i_entry++) {
					pEntry = PyList_GetItem(pReturn, i_entry);
					pKey = PyTuple_GetItem(pEntry, 0);
					pValue = PyTuple_GetItem(pEntry, 1);
					entries[i_entry].key_state =
						PyInt_AsLong(PyTuple_GetItem(pKey, 0));
					entries[i_entry].key_unit =
						(PyString_AsString(PyTuple_GetItem(pKey, 1)))[0];
					entries[i_entry].value_state =
						PyInt_AsLong(PyTuple_GetItem(pValue, 0));
					entries[i_entry].value_flag =
						PyInt_AsLong(PyTuple_GetItem(pValue, 1));
				}
				*result = entries;
				Py_DECREF(pKey);
				Py_DECREF(pValue);
				Py_DECREF(pEntry);
			}
			else {
				Py_DECREF(pFunc);
				Py_DECREF(pModule);
				PyErr_Print();
				fprintf(stderr,"Call failed\n");
				return -1;
			}
		}
		else {
			if (PyErr_Occurred())
				PyErr_Print();
				fprintf(stderr, "Cannot find function \"str2dfa\"\n");
		}
	}
	else {
		PyErr_Print();
		fprintf(stderr, "Failed to load \"str2dfa\"\n");
		return -1;
	}
	Py_Finalize();
	return n_entry;
}

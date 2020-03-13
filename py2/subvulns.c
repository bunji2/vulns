#include "subvulns.h"

/* dict に object をセットする */

int dictSetObj(PyObject*dict, char*key, PyObject*value) {
    if (PyDict_SetItemString(dict, key, value)<0) {
        return -1;
    }
    return 0;
}

/* dict に string をセットする */
int dictSetStr(PyObject*dict, char*key, char*value) {
    if (PyDict_SetItemString(dict, key, PyString_FromString(value))<0) {
        return -1;
    }
    return 0;
}

/* list に文字列を追加する */

int listAppendStr(PyObject*list, char*str) {
    if (PyList_Append(list, PyString_FromString(str))<0) {
        return -1;
    }
    return 0;
}

/* new empty list */
PyObject* newList() {
    return PyList_New((Py_ssize_t)0);
}

/*
PyObject* PyDict_New()
Return value: New reference.
空の新たな辞書を返します。失敗すると NULL を返します。

int PyDict_SetItemString(PyObject *p, const char *key, PyObject *val)
辞書 p に、 key をキーとして値 value を挿入します。 key は char* 型でなければなりません。キーオブジェクトは PyString_FromString(key) で生成されます。成功した場合には 0 を、失敗した場合には -1 を返します。

*/


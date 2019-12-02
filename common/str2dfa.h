/*************************************************************************
	> File Name: str2dfa.h
	> Author: 
	> Mail: 
	> Created Time: Mon 02 Dec 2019 03:01:09 PM CST
 ************************************************************************/

#ifndef _STR2DFA_H
#define _STR2DFA_H

struct str2dfa_kv {
	long key_state;
	char key_unit;
	long value_state;
	long value_is_acceptable;
};

int str2dfa(char **, int , struct str2dfa_kv **);

#endif

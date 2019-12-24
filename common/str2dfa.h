/*************************************************************************
	> File Name: str2dfa.h
	> Author: Guanyu Li
	> Mail: dracula.register@gmail.com
	> Created Time: Mon 02 Dec 2019 03:01:09 PM CST
 ************************************************************************/

#ifndef _STR2DFA_H
#define _STR2DFA_H

struct dfa_struct {
	uint32_t entry_number;
	struct dfa_entry *entries;
};

struct dfa_entry {
	uint16_t key_state;
	uint8_t key_unit;
	uint16_t value_state;
	uint16_t value_flag;
};

int str2dfa(char **, int, struct dfa_struct *);
int str2dfa_fromfile(const char *, struct dfa_struct *result);

#endif

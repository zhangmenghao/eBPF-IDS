/*************************************************************************
	> File Name: re2dfa.h
	> Author: 
	> Mail: 
	> Created Time: Wed 27 Nov 2019 03:11:28 PM CST
 ************************************************************************/

#ifndef _RE2DFA_H
#define _RE2DFA_H

#define REMAX 600

struct dfaMatrix {
	int *set;
	char state;
	//stores the dfa structure..
};

struct dfaObject {
    struct dfaMatrix dfa[REMAX][REMAX];
    char uniqueSymbols[REMAX];
    int symbolCount;
    int noOfInputs;
    int newStates;
};

void printObjectDFA(struct dfaObject* targetDFA);
void printObjectMappedDFA(struct dfaObject* targetDFA);
int re2dfa(char* originREString, struct dfaObject* targetDFA);

#endif

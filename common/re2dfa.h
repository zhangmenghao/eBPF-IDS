#ifndef _RE2DFA_H
#define _RE2DFA_H

#include <stdio.h>
#include <stdlib.h>

/*******************************************************************************
******************            Generic-List Macro              ******************
*******************************************************************************/

#define INITIAL_CAPACITY  8     /* default capacity value for newly created
                                 * generic list */

/* Interface wrapper for __create_generic_list */
#define create_generic_list(type, glist)                                \
    __create_generic_list(sizeof(type), INITIAL_CAPACITY, glist)

/* Compare function template for POD types */
#define MAKE_COMPARE_FUNCTION(postfix, type) \
    static int __cmp_##postfix (const void *a_, const void *b_)         \
    {                                                                   \
        type a = *((type*) a_);                                         \
        type b = *((type*) b_);                                         \
        if (a < b) return -1;                                           \
        else if (a > b) return 1;                                       \
        else return 0;                                                  \
    }

/*******************************************************************************
******************          Generic-List Structure            ******************
*******************************************************************************/

/* Generic linear data structure similar to std::vector in C++, this structure
 * is also used as sets although it would be very inefficient. */
struct generic_list
{
    int elem_size;   /* size of each element */
    int length;      /* num of elements in the list */
    int capacity;    /* capacity of this list, can be expanded dynamically */
    char *p_dat;     /* pointer to actual data */
};

/*******************************************************************************
******************               NFA Structure                ******************
*******************************************************************************/

/* definition of some transition characters. 
   (NFATT here means "NFA transition type") */
enum NFA_transition_type {
    NFATT_NONE,        /* placeholder */
    NFATT_CHARACTER,   /* "traditional" transition */
    NFATT_EPSILON      /* epsilon transition */
};

/* Transition from one NFA state to another */
struct NFA_transition
{
    /* type of the transition. It can be an epsilon transition, traditional
     * character transition, or just a placeholder  */
    enum NFA_transition_type trans_type;
    char trans_char;   /* If trans_type is TT_CHARACTER, then trans_char
                        * indicates the transition label */
};

/* state in NFA, each state has at most 2 transitions if the NFA is constructed
 * from basic constructs of regular expressions. */
struct NFA_state
{
    struct NFA_state      *to[2];          /* destination of transition */
    struct NFA_transition  transition[2];  /* transitions from this state */
};

/* Non determined automata (NFA) */
struct NFA
{
    struct NFA_state *start;     /* start state */
    struct NFA_state *terminate; /* terminate state */

    /* Notice that there should be only one terminate state if the NFA is
     * constructed purly from basic regular expression constructs */
};

/*******************************************************************************
******************               DFA Structure                ******************
*******************************************************************************/

struct DFA_state;   /* forward type declaration */

/* Transition of a DFA state */
struct DFA_transition
{
    struct DFA_state *to;   /* destination of the transition */
    char trans_char;        /* transition character */
};

/* State in DFA, it can also be used to represent an entire DFA if it is a
 * start state */
struct DFA_state
{
    int is_acceptable;      /* if this state is an acceptable state */

    struct DFA_transition *trans;  /* an array of transitions going out from
                                    * this state */
    int n_transitions;             /* number of transitions  */
    int state_id;                  /* the identifier of state */
    int _capacity;                 /* reserved space for transitions */
};

/* In the NFA to DFA process, multiple NFA states were merged to an unique DFA
 * state. An DFA state entry is an correspondence between a set of NFA states
 * label (addr) and an DFA state. */
struct __dfa_state_entry
{
    struct generic_list nfa_states;    /* set of NFA states */
    struct DFA_state   *dfa_state;     /* corresponded DFA state */
};

/* Each state set contains one or more DFA states, DFA optimization procedure
 * is to merge multiple undistinguished states to one unique state, which
 * decreases the number of states/transitions of the resulting DFA.
 *
 * We have a generic list named dfa_states containing all DFA states in this
 * state set, it is also equiped with a pair of pointers to make it a node in a
 * linked list, the linked list represents the resulting DFA, and each node
 * (state set) is a state of it.
 */

struct __DFA_state_set
{
    struct __DFA_state_set *prev;
    struct __DFA_state_set *next;

    struct generic_list dfa_states;  /* one or multiple DFA states merged up to
                                      * this state set*/
    struct DFA_state *merged_state;  /* DFA state created for this merged
                                      * state */
};

/*******************************************************************************
******************           Generic-List Function            ******************
*******************************************************************************/

/* Create a generic list for some kind of data elements, elem_size specified
 * the size in bytes of each data element, initial_capacity is the amount of
 * space reserved for furture use (it cannot be zero). */
void __create_generic_list(
    int elem_size, int initial_capacity, struct generic_list *glist);

void generic_list_duplicate(
    struct generic_list *dest, const struct generic_list *src);

/* Find element in the list using specified compare function, it returns the
 * pointer to the element found in the list, or a NULL is returned if *elem is
 * not in glist */
void *generic_list_find(
    struct generic_list *glist, const void *elem, 
    int(*cmp)(const void*, const void*));

/* Add an element to the list only if this element is not in the list (we
 * actually regard the glist as a set). It would return 1 if *elem is actually
 * appended, or it would return 0 when there's already an *elem in the list. */
int generic_list_add(
    struct generic_list *glist, const void *elem, 
    int(*cmp)(const void*, const void*));

/* Free the memory allocated for the generic list */
void destroy_generic_list(struct generic_list *glist);

/* Append an element to the tail of specified generic list */
void generic_list_push_back(struct generic_list *glist, const void *elem);

/* Remove the last element in the list */
void generic_list_pop_back(struct generic_list *glist);

/* Get the pointer to the element on the tail of the list */
void *generic_list_back(struct generic_list *glist);

/* Get pointer to the first element  */
void *generic_list_front(struct generic_list *glist);

/* Empty the generic list */
void generic_list_clear(struct generic_list *glist);

/*******************************************************************************
******************                NFA Function                ******************
*******************************************************************************/

/* Create a new isolated NFA state, there's no transitions going out of it */
struct NFA_state *alloc_NFA_state(void);

/* Free allocated space for specified NFA state */
void free_NFA_state(struct NFA_state *state);

/* get number of transitions going out from specified NFA state */
int NFA_state_transition_num(const struct NFA_state *state);

/* Add another transition to specified NFA state, this function returns 0 on
 * success, or it would return an -1 when there's already 2 transitions going
 * out of this state */
int NFA_state_add_transition(struct NFA_state *state, 
    enum NFA_transition_type trans_type, char trans_char, 
    struct NFA_state *to_state);

/* Add an epsilon transition from "from" to "to" */
int NFA_epsilon_move(struct NFA_state *from, struct NFA_state *to);

/* DEBUGGING ROUTINE: dump specified NFA state to fp */
void __dump_NFA_state(const struct NFA_state *state, FILE *fp);

/* Dump DOT code to vizualize specified NFA */
void NFA_dump_graphviz_code(const struct NFA *nfa, FILE *fp);

/* Check if the string matches the pattern implied by the nfa */
int NFA_pattern_match(const struct NFA *nfa, const char *str);

/* The smallest building block of regexp-NFA */
struct NFA NFA_create_atomic(char c);                                 /* c   */

/* Operators in regular expression, we could assemble NFAs with these methods
 * to build our final NFA for the regular expression. */
struct NFA NFA_concatenate(const struct NFA *A, const struct NFA *B); /* AB  */
struct NFA NFA_alternate(const struct NFA *A, const struct NFA *B);   /* A|B */
struct NFA NFA_optional(const struct NFA *A);                         /* A?  */
struct NFA NFA_Kleene_closure(const struct NFA *A);                   /* A*  */
struct NFA NFA_positive_closure(const struct NFA *A);                 /* A+  */

/* Compile basic regular expression to NFA */
struct NFA reg_to_NFA(const char *regexp);

/* Free an NFA */
void NFA_dispose(struct NFA *nfa);

/*******************************************************************************
******************                DFA Function                ******************
*******************************************************************************/

/* Create an empty (isolated), non-acceptable state */
struct DFA_state *alloc_DFA_state(void);

/* Free allocated space for specified DFA state */
void free_DFA_state(struct DFA_state *state);

/* Destroy the entire DFA */
void DFA_dispose(struct DFA_state *start);

/* Turn specified DFA state to an acceptable one */
void DFA_make_acceptable(struct DFA_state *state);

/* Add transition between specified DFA states

       /----\  trans_char  /--\
       |from|------------>>|to|
       \----/              \--/
*/
void DFA_add_transition(
    struct DFA_state *from, struct DFA_state *to, char trans_char);

/* Get the target state of specified state under certain transition, if there's
 * no such transition then NULL is returned */
struct DFA_state *DFA_target_of_trans(
    struct DFA_state *state, char trans_char);

/* Traverse from specified state and add all reachable states to a generic
 * list */
void DFA_traverse(
    struct DFA_state *state, struct generic_list *visited);

/* Generate DOT code to vizualize the DFA */
void DFA_dump_graphviz_code(const struct DFA_state *start_state, FILE *fp);

/* Convert an NFA to DFA, this function returns the start state of the
 * resulting DFA */
struct DFA_state *NFA_to_DFA(const struct NFA *nfa);

/* Simplify DFA by merging undistinguishable states */
struct DFA_state *DFA_optimize(const struct DFA_state *dfa);

/* The high-level interface for other programs */
struct DFA_state *re2dfa(char *re_string);

#endif

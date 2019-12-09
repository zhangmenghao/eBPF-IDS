#!/usr/bin/env python
# coding=utf-8

import ahocorasick

class DFAMatchEntriesGenerator():
    def __init__(self, pattern_list, stride=1, table_id=0):
        # Init and configure the automaton
        self.stride = stride
        self.table_id = table_id
        self.automaton = ahocorasick.Automaton(ahocorasick.STORE_LENGTH)
        if type(pattern_list) == list:
            for pattern in pattern_list:
                self.automaton.add_word(pattern)
        elif type(pattern_list) == str:
            pattern_file = open(pattern_list, 'r')
            for pattern in pattern_file.readlines():
                pattern = pattern[:-1]
                print("Get pattern of length %d: %s" % (len(pattern), pattern))
                self.automaton.add_word(pattern)
        self.automaton.make_automaton()
        # Gegerate dfa descriptor according to the automaton
        self.dfa = self.generate_dfa(self.automaton.dump())
        self.msdfa = self.generate_multi_stride_dfa(self.dfa, self.stride)
        self.mat_entries = self.generate_mat_entries(self.msdfa)
        self.key_value_entries = self.generate_key_value_entries(self.msdfa)

    def generate_dfa(self, automaton_graph_descriptor):
        nodes = automaton_graph_descriptor[0]
        edges = automaton_graph_descriptor[1]
        failure_links = automaton_graph_descriptor[2]
        converse_dict = {}
        dfa_nodes = {}
        dfa_edges = []
        dfa_failure_links = []
        dfa_next_nodes = {}
        pattern_idx = 0
        for node_id in range(len(nodes)):
            origin_node_id = nodes[node_id][0]
            converse_dict[origin_node_id] = node_id
            accept_flag = nodes[node_id][1]
            if accept_flag == 1:
                pattern_idx += 1
                accept_flag = pattern_idx
            dfa_nodes[node_id] = accept_flag
            dfa_next_nodes[node_id] = []
        for edge in edges:
            start_node_id = converse_dict[edge[0]]
            transfer_char = edge[1]
            end_node_id = converse_dict[edge[2]]
            dfa_edges.append(
                (start_node_id, transfer_char, end_node_id, 1)
            )
            dfa_next_nodes[start_node_id].append(
                (transfer_char, end_node_id)
            )
        for failure_link in failure_links:
            start_node_id = converse_dict[failure_link[0]]
            intermediate_node_id = converse_dict[failure_link[1]]
            dfa_failure_links.append((start_node_id, intermediate_node_id))
            # # Below condition statements indicate what we care about is 
            # # the input whether hit one of the patterns, not all patterns
            # if dfa_nodes[start_node_id] ! = 0:
                # continue
            for next_node in dfa_next_nodes[intermediate_node_id]:
                transfer_char = next_node[0]
                end_node_id = next_node[1]
                cover_flag = False
                # Check whether this failure link endge is valid
                for origin_next_node in dfa_next_nodes[start_node_id]:
                    existing_transfer_char = origin_next_node[0]
                    cover_flag = True
                    if transfer_char != existing_transfer_char \
                       and ord(b'\xff') != existing_transfer_char:
                        cover_flag = False
                if not cover_flag:
                    dfa_edges.append(
                        (start_node_id, transfer_char, end_node_id, 0)
                    )
        return (dfa_nodes, dfa_edges, dfa_failure_links, dfa_next_nodes)

    def generate_multi_stride_dfa(self, dfa_descriptor, stride):
        dfa_nodes = dfa_descriptor[0]
        dfa_edges = dfa_descriptor[1]
        dfa_failure_links = dfa_descriptor[2]
        dfa_next_nodes = dfa_descriptor[3]
        dfa_next_nodes_extend = {}
        msdfa_nodes = dfa_nodes
        msdfa_edges = []
        msdfa_next_nodes = {}
        for dfa_node_id in dfa_nodes:
            dfa_next_nodes_extend[dfa_node_id] = dfa_next_nodes[dfa_node_id][:]
            msdfa_next_nodes[dfa_node_id] = []
        # Extend single stride DFA first
        for (start_node_id, transfer_char, end_node_id, type) in dfa_edges:
            if start_node_id == 0 and type == 1:
                for star_num in range(1, stride):
                    transfer_chars = b'\xff' * star_num + transfer_char
                    dfa_next_nodes_extend[start_node_id].append(
                        (transfer_chars, end_node_id)
                    )
            if dfa_nodes[end_node_id] != 0 and type == 1:
                for star_num in range(1, stride):
                    transfer_chars = transfer_char + b'\xff' * star_num
                    dfa_next_nodes_extend[start_node_id].append(
                        (transfer_chars, end_node_id)
                    )
        # Get all transistion edges of multi-stride DFA
        for dfa_node in dfa_nodes:
            start_node_id = dfa_node
            self.find_multi_stride_edges(
                msdfa_edges, msdfa_next_nodes, dfa_next_nodes_extend, \
                start_node_id, b'', start_node_id, stride
            )
        # Process failure links finally
        for failure_link in dfa_failure_links:
            start_node_id = failure_link[0]
            # # Below condition statements indicate what we care about is 
            # # the input whether hit one of the patterns, not all patterns
            # if msdfa_next_nodes[start_node_id] != 0:
                # continue
            intermediate_node_id = failure_link[1]
            for next_node in msdfa_next_nodes[intermediate_node_id]:
                transfer_chars = next_node[0]
                end_node_id = next_node[1]
                cover_flag = False
                # Check whether this failure link endge is valid
                for origin_next_node in msdfa_next_nodes[start_node_id]:
                    existing_path = origin_next_node[0]
                    cover_flag = True
                    for idx in range(stride):
                        if transfer_chars[idx] != existing_path[idx] \
                           and ord(b'\xff') != existing_path[idx]:
                            cover_flag = False
                            break
                if not cover_flag:
                    msdfa_edges.append(
                        (start_node_id, transfer_chars, end_node_id, 0)
                    )
        return (msdfa_nodes, msdfa_edges)

    def find_multi_stride_edges(self, msdfa_edges, msdfa_next_nodes, \
                                dfa_next_nodes, start_node_id, \
                                current_path, current_node_id, stride):
        for next_node in dfa_next_nodes[current_node_id]:
            next_path = current_path + next_node[0]
            next_node_id = next_node[1]
            if len(next_path) < stride:
                self.find_multi_stride_edges(
                    msdfa_edges, msdfa_next_nodes, dfa_next_nodes, \
                    start_node_id, next_path, next_node_id, stride
                )
            elif len(next_path) == stride:
                transfer_chars = next_path
                end_node_id = next_node_id
                msdfa_edges.append(
                    (start_node_id, transfer_chars, end_node_id, 1)
                )
                msdfa_next_nodes[start_node_id].append(
                    (transfer_chars, end_node_id)
                )
            else:
                continue
    
    def generate_mat_entries(self, msdfa_descriptor):
        msdfa_nodes = msdfa_descriptor[0]
        msdfa_edges = msdfa_descriptor[1]
        mat_entries = []
        for (current_state, received_chars, next_state, type) in msdfa_edges:
            match = (current_state, received_chars)
            # if msdfa_nodes[next_state] != 0:
                # action = 'accept'
            # else:
                # action = 'goto'
            action = 'goto'
            modifier = 0
            if msdfa_nodes[next_state] != 0:
                modifier = 1 << (msdfa_nodes[next_state] - 1)
            action_params = (next_state, modifier)
            mat_entries.append((match, action, action_params))
        return mat_entries

    def generate_key_value_entries(self, msdfa_descriptor):
        msdfa_nodes = msdfa_descriptor[0]
        msdfa_edges = msdfa_descriptor[1]
        key_value_entries = []
        for (current_state, received_chars, next_state, type) in msdfa_edges:
            key = (current_state, received_chars)
            value = (next_state, msdfa_nodes[next_state])
            key_value_entries.append((key, value))
        return key_value_entries

    def get_automaton(self):
        return self.automaton

    def get_dfa(self):
        return self.dfa

    def get_multi_stride_dfa(self):
        return self.msdfa

    def get_mat_entries(self):
        return self.mat_entries

    def get_key_value_entries(self):
        return self.key_value_entries

def str2dfa(pattern_list):
    entries_generator = DFAMatchEntriesGenerator(pattern_list, 1)
    return entries_generator.get_key_value_entries()

if __name__ == '__main__':
    x = DFAMatchEntriesGenerator(['dog', 'cat'], 1)
    for i in x.get_key_value_entries():
        print(i)

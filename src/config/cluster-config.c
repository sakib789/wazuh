/*
 * Cluster settings manager
 * Copyright (C) 2015, Wazuh Inc.
 * Oct 16, 2017.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "shared.h"
#include "config.h"
#include "global-config.h"


int Read_Cluster(XML_NODE node, void *d1, __attribute__((unused)) void *d2) {

    static const char *disabled = "disabled";
    static const char *cluster_name = "name";
    static const char *node_name = "node_name";
    static const char *node_type = "node_type";
    static const char *key = "key";
    static const char *socket_timeout = "socket_timeout";
    static const char *connection_timeout = "connection_timeout";
    static const char *interval = "interval";
    static const char *nodes = "nodes";
    static const char *hidden = "hidden";
    static const char *port = "port";
    static const char *bind_addr = "bind_addr";
    static const char *C_VALID = "!\"#$%&'-.0123456789:<=>?ABCDEFGHIJKLMNOPQRESTUVWXYZ[\\]^_abcdefghijklmnopqrstuvwxyz{|}~";

    xml_node **children = NULL;
    static const char *haproxy_helper = "haproxy_helper";
    static const char *haproxy_address = "haproxy_address";
    static const char *haproxy_port = "haproxy_port";
    static const char *haproxy_user = "haproxy_user";
    static const char *haproxy_password = "haproxy_password";
    static const char *excluded_nodes = "excluded_nodes";
    static const char *frequency = "frequency";
    static const char *agent_chunk_size = "agent_chunk_size";
    static const char *agent_reconnection_time = "agent_reconnection_time";
    static const char *agent_reconnection_stability_time = "agent_reconnection_time";
    static const char *imbalance_tolerance = "imbalance_tolerance";
    static const char *remove_disconnected_node_after = "remove_disconnected_node_after";

    _Config *Config;
    Config = (_Config *)d1;
    int i;
    int disable_cluster_info = 0;

    Config->hide_cluster_info = 0;

    for (i = 0; node[i]; i++) {
        if (!node[i]->element) {
            merror(XML_ELEMNULL);
            return OS_INVALID;
        } else if (!node[i]->content) {
            merror(XML_VALUENULL, node[i]->element);
            return OS_INVALID;
        } else if (!strcmp(node[i]->element, cluster_name)) {
            if (!strlen(node[i]->content)) {
                merror("Cluster name is empty in configuration");
                return OS_INVALID;
            } else if (strspn(node[i]->content, C_VALID) < strlen(node[i]->content)) {
                merror("Detected a not allowed character in cluster name: \"%s\". Characters allowed: \"%s\".", node[i]->content, C_VALID);
                return OS_INVALID;
            }
            os_strdup(node[i]->content, Config->cluster_name);
        } else if (!strcmp(node[i]->element, node_name)) {
            if (!strlen(node[i]->content)) {
                merror("Node name is empty in configuration");
                return OS_INVALID;
            } else if (strspn(node[i]->content, C_VALID) < strlen(node[i]->content)) {
                merror("Detected a not allowed character in node name: \"%s\". Characters allowed: \"%s\".", node[i]->content, C_VALID);
                return OS_INVALID;
            }
            os_strdup(node[i]->content, Config->node_name);
        } else if (!strcmp(node[i]->element, node_type)) {
            if (!strlen(node[i]->content)) {
                merror("Node type is empty in configuration");
                return OS_INVALID;
            } else if (strcmp(node[i]->content, "worker") && strcmp(node[i]->content, "client") && strcmp(node[i]->content, "master") )  {
                merror("Detected a not allowed node type '%s'. Valid types are 'master' and 'worker'.", node[i]->content);
                return OS_INVALID;
            }
            os_strdup(node[i]->content, Config->node_type);
        } else if (!strcmp(node[i]->element, key)) {
        } else if (!strcmp(node[i]->element, socket_timeout)) {
        } else if (!strcmp(node[i]->element, connection_timeout)) {
        } else if (!strcmp(node[i]->element, disabled)) {
            if (strcmp(node[i]->content, "yes") && strcmp(node[i]->content, "no")) {
                merror("Detected a not allowed value for disabled tag '%s'. Valid values are 'yes' and 'no'.", node[i]->content);
                return OS_INVALID;
            }
            if (strcmp(node[i]->content, "yes") == 0) {
                disable_cluster_info = 1;
            }
        } else if (!strcmp(node[i]->element, hidden)) {
            if (strcmp(node[i]->content, "yes") == 0) {
                Config->hide_cluster_info = 1;
            } else if (strcmp(node[i]->content, "no") == 0) {
                Config->hide_cluster_info = 0;
            } else {
                merror(XML_VALUEERR, node[i]->element, node[i]->content);
                return OS_INVALID;
            }
        } else if (!strcmp(node[i]->element, interval)) {
            mwarn("Detected a deprecated configuration for cluster. Interval option is not longer available.");
        } else if (!strcmp(node[i]->element, nodes)) {
        } else if (!strcmp(node[i]->element, port)) {
        } else if (!strcmp(node[i]->element, bind_addr)) {
        } else if (!strcmp(node[i]->element, haproxy_helper)) {
            children = OS_GetElementsbyNode(xml, nodes[i])

            if (!children) {
                continue;
            }

            for (j = 0; children[j]; j++) {
                if (!strcmp(children[j]->child, disabled)) {
                        if (strcmp(children[j]->child, "yes") && strcmp(children[j]->child, "no")) {
                        merror("Detected a not allowed value for disabled tag '%s'. Valid values are 'yes' and 'no'.", children[j]->child);
                        return OS_INVALID;
                    }
                } else if (!strcmp(children[j]->child, frequency) {

                } else if (!strcmp(children[j]->child, haproxy_address) {

                } else if (!strcmp(children[j]->child, haproxy_port) {

                } else if (!strcmp(children[j]->child, haproxy_user) {

                } else if (!strcmp(children[j]->child, haproxy_password) {

                } else if (!strcmp(children[j]->child, excluded_nodes) {

                } else if (!strcmp(children[j]->child, agent_chunk_size) {

                } else if (!strcmp(children[j]->child, agent_reconnection_time) {

                } else if (!strcmp(children[j]->child, agent_reconnection_stability_time) {

                } else if (!strcmp(children[j]->child, imbalance_tolerance) {

                } else if (!strcmp(children[j]->child, remove_disconnected_node_after) {

                } else {
                    merror(XML_INVELEM, children[i]->child);
                    return OS_INVALID;
                }

        } else {
            merror(XML_INVELEM, node[i]->element);
            return OS_INVALID;
        }
    }

    if (disable_cluster_info)
        Config->hide_cluster_info = 1;

    return 0;
 }

// <cluster>
//     <haproxy_helper>
//       <disabled>yes</disabled>
//       <frequency>60</frequency>
//       <haproxy_address></haproxy_address>
//       <haproxy_port></haproxy_port>
//       <haproxy_user></haproxy_user>
//       <haproxy_password></haproxy_password>
//       <excluded_nodes>
//         <node>master</node>
//       </excluded_nodes>
//       <agent_chunk_size>100</agent_chunk_size>
//       <agent_reconnection_time>5</agent_reconnection_time>
//       <imbalance_tolerance>10</imbalance_tolerance>
//       <remove_disconnected_node_after>60</remove_disconnected_node_after>
//     </haproxy_helper>
// </cluster>
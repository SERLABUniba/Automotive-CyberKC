# -*- coding: utf-8 -*-
"""
Created on Wed Dec  6 11:08:30 2023

@author: Guido
"""

'''

Questo script serve per l'invio di payload a QRadar partendo da un file csv. Di seguito le
spiegazioni dei metodi
    
    - load_dataset(file_path): legge il dataset in formato csv, crea un header e restituisce
                               un dataframe
                               
    - add_spaces(input_string): facoltativo, semplice metodo di formattazione della stringa relativa al campo
                                DATA CAN. Aggiunge uno spazio dopo ogni blocco di 4 bit della stringa di input
                                
    - send_payload(payload, udp_socket, host_and_port): dato un payload in formato JSON, utilizza
                                                        udp_socket per inviarlo a host_and_port
                                                        
    - inject_payloads_from_dataset(path_to_dataset, log_file_name, start, end): contiene la logica dell'invio dei dati

    - send_debug_payload(timestamp, id_can, data_can, label): costruisce un payload di test sulla base di timestamp, id_can
                                                              e data_can e lo invia al SIEM

'''

import pandas as pd
import socket
import json
import csv
import argparse

udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

host_and_port = ('127.0.0.1', 5144)

def read_csv(file_path):
    
    values_list = []

    with open(file_path, 'r') as csv_file:
        
        csv_reader = csv.reader(csv_file)
        
        for row in csv_reader:
            values_list.extend(row)

    return values_list

def load_dataset(file_path):
    
    df = pd.read_csv(file_path, header=None)

    column_names = ['Timestamp', 'ID CAN', 'DLC', 'DATA0', 'DATA1', 'DATA2', 'DATA3', 'DATA4', 'DATA5', 'DATA6', 'DATA7', 'label']

    df.columns = column_names
    
    return df

def add_spaces(input_string):
    
    result = ''
    
    for i in range(0, len(input_string), 2):
        result += input_string[i:i+2] + ' '
        
    return result.strip()

def send_payload(payload, udp_socket, host_and_port):
    
    try:
        
        udp_socket.sendto(payload.encode("utf-8"), host_and_port)
        
        print("...PAYLOAD SENT SUCCESSFULLY")
        
    except Exception as e:
        
        print(f"Errore durante l'invio dei dati a QRadar: {str(e)}")

def send_debug_payload(timestamp, id_can, data_can, label):
    
    payload = {
    
        "UUID" : "63cd3082a04",
        "eventID" : "CAN Payload",
        "eventCategory" : "SpoofingGear",
        "Timestamp" : timestamp,
        "ID CAN" : id_can,
        "DATA CAN" : add_spaces(data_can),
        "label" : label
        
    }
    
    print(json.dumps(payload))
    
    send_payload(json.dumps(payload), udp_socket, host_and_port)

def inject_payloads_from_dataset(path_to_dataset, log_file_name, start, end):

    df = load_dataset(path_to_dataset)
    
    # idCanR = read_csv('id_can_R.csv')
    
    count_offenses = 0

    count2 = 0
    
    # count_false_positive = 0
    
    if(end == 0):
        end = df.shape[0]
    
    with open(log_file_name, 'a', newline='') as log:

        for index, row in df.iloc[start-1:end].iterrows():
            
            print('Sending payload N. ' + str(index + 1) + '...\t' + 'Class: ' + row[11])
            
            row_values = row.tolist()
            
            if(row_values[11] == 'T'):
                count_offenses += 1

            payload = {
            
                "UUID" : "63cd3082a04",
                "eventID" : "CAN Payload",
                "eventCategory" : "SpoofingGear",
                "Timestamp" : row_values[0],
                "ID CAN" : row_values[1],
                "DATA CAN" : add_spaces(row_values[3] + row_values[4] + row_values[5] + row_values[6] + row_values[7] + row_values[8] + row_values[9] + row_values[10]),
                "label" : row_values[11]
                
            }
            
            json_payload = json.dumps(payload)
            
            print(json_payload)

            writer = csv.writer(log)
            writer.writerow(row_values)

            send_payload(json_payload, udp_socket, host_and_port)

            print('-----------------------------------------------------------------------------------------------------------------------------------------')
        
    print('Total offenses = ' + str(count_offenses))
    # print('Total false positive = ' + str(count_false_positive))
        
    udp_socket.close()

try:
    
    parser = argparse.ArgumentParser(description = 'Choose a dataset and send payloads to the SIEM')
    
    parser.add_argument('-d', help = 'Path to the dataset', required = True)
    parser.add_argument('-end', help = 'Number of payloads to send (if 0, the whole dataset will be processed)', required = True)
    parser.add_argument('-start', help = 'Start from payload n. ?', required = True)
    parser.add_argument('-log', help = 'Name of the log file (in .csv format)', required = False)
    
    args = parser.parse_args()
    
    # Spoofing RPM
    # send_debug_payload(1478195722.800121, '0316', '452924ff292400ff', 'T') 

    # Spoofing Gear
    # send_debug_payload(1478195722.800121, '043f', '014560ff6b000000', 'T') 
    
    inject_payloads_from_dataset(args.d, args.log, int(args.start), int(args.end))
    
except Exception as e:
    
    print(f"An error occurred: {str(e)}")
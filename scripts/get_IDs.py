#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Thu Dec 28 09:51:03 2023

@author: guido
"""

import os
import pandas as pd
import csv

OUTPUT_FILE_NAME = 'output.csv'

def read_csv(file_name):
    
    df = pd.read_csv(file_name, header=None)
    
    return df

def write_set_to_csv(set_id_can, csv_file_path):
    
    lst = list(set_id_can)

    with open(csv_file_path, 'a', newline='') as csv_file:
        
        csv_writer = csv.writer(csv_file)        
        
        for item in lst:
            
            csv_writer.writerow([item])

def main():
    
    list_id_can = []
    
    for file in os.listdir():
        
        if(file.endswith('.csv') and file != OUTPUT_FILE_NAME):
            
            print('Reading ' + file + '...')
            
            df = read_csv(file)
            
            print('... file read successfully')
            
            for index, row in df.iloc[0:df.shape[0]].iterrows():
                
                row_values = row.tolist()
                
                if(row_values[11] == 'R'):
                
                    id_can = row_values[1]
                    
                    print(id_can)
                    
                    list_id_can.append(id_can)
                
            set_id_can = set(list_id_can)
            
    write_set_to_csv(set_id_can, OUTPUT_FILE_NAME)
                    
main()
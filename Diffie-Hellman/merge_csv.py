import pandas as pd

client_df = pd.read_csv('client_timings_dh.csv')
server_df = pd.read_csv('server_timings_dh.csv')

client_df.columns = ['Iteration', 'Client Key Generation Time', 'Client Shared Secret Time', 'Client AES Encryption Time']
server_df.columns = ['Iteration', 'Server Key Generation Time', 'Server Shared Secret Time', 'Server AES Decryption Time']

server_data = server_df.drop('Iteration', axis=1)

merged_df = pd.concat([client_df.iloc[:len(server_df)], server_data], axis=1)

merged_df.to_csv('diffie-hellman.csv', index=False, float_format='%.6f')

print(f"CSV-Dateien erfolgreich zusammengeführt! {len(merged_df)} vollständige Messungen.")
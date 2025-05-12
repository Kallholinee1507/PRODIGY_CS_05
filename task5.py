import threading
import time
from datetime import datetime
import pandas as pd
from scapy.all import sniff, IP, TCP, UDP, ICMP, Raw
from dash import Dash, html, dcc, dash_table
from dash.dependencies import Input, Output, State
import base64

packet_data = []
MAX_ROWS = 200

def get_protocol(pkt):
    if pkt.haslayer(TCP):
        return "TCP"
    elif pkt.haslayer(UDP):
        return "UDP"
    elif pkt.haslayer(ICMP):
        return "ICMP"
    return "Other"

def get_payload(pkt, show_hex=False):
    if pkt.haslayer(Raw):
        raw = pkt[Raw].load[:100]
        if show_hex:
            return raw.hex()
        try:
            return raw.decode('utf-8')
        except:
            return "<encrypted or binary data>"
    return "<no payload>"

def process_packet(pkt):
    if IP in pkt:
        record = {
            'Timestamp': datetime.now().strftime("%H:%M:%S"),
            'Source IP': pkt[IP].src,
            'Destination IP': pkt[IP].dst,
            'Protocol': get_protocol(pkt),
            'Payload (ASCII)': get_payload(pkt, show_hex=False),
            'Payload (Hex)': get_payload(pkt, show_hex=True)
        }
        packet_data.append(record)
        if len(packet_data) > MAX_ROWS:
            packet_data.pop(0)

def sniff_packets():
    sniff(filter="ip", prn=process_packet, store=0)

# Background sniffing
threading.Thread(target=sniff_packets, daemon=True).start()

app = Dash(__name__)
app.title = "Advanced Network Packet Analyzer"

app.layout = html.Div([
    html.H2("Live Network Packet Analyzer (Educational Use Only)"),

    html.Div([
        html.Label("Protocol Filter:"),
        dcc.Dropdown(
            id='protocol-filter',
            options=[
                {'label': 'All', 'value': 'All'},
                {'label': 'TCP', 'value': 'TCP'},
                {'label': 'UDP', 'value': 'UDP'},
                {'label': 'ICMP', 'value': 'ICMP'},
            ],
            value='All',
            clearable=False,
            style={'width': '150px'}
        ),
        html.Label("Search IP:"),
        dcc.Input(id='search-ip', type='text', placeholder='Enter IP...', debounce=True),
        html.Label("Payload View:"),
        dcc.RadioItems(
            id='payload-view',
            options=[
                {'label': 'ASCII', 'value': 'ascii'},
                {'label': 'Hex', 'value': 'hex'}
            ],
            value='ascii',
            inline=True
        ),
        html.Button("Export CSV", id="export-btn"),
        dcc.Download(id="download-csv")
    ], style={'display': 'flex', 'gap': '20px', 'marginBottom': '20px'}),

    dash_table.DataTable(
        id='packet-table',
        columns=[
            {"name": i, "id": i} for i in ['Timestamp', 'Source IP', 'Destination IP', 'Protocol', 'Payload']
        ],
        data=[],
        style_table={'overflowX': 'auto'},
        style_cell={'whiteSpace': 'normal', 'textAlign': 'left'},
        style_header={'fontWeight': 'bold'},
        page_size=10
    ),

    dcc.Interval(id='interval', interval=2000, n_intervals=0)
])

@app.callback(
    Output('packet-table', 'data'),
    Output('packet-table', 'columns'),
    Input('interval', 'n_intervals'),
    Input('protocol-filter', 'value'),
    Input('search-ip', 'value'),
    Input('payload-view', 'value'),
)
def update_table(n, proto, search_ip, payload_view):
    view_key = 'Payload (ASCII)' if payload_view == 'ascii' else 'Payload (Hex)'
    filtered = []

    for pkt in packet_data:
        if proto != 'All' and pkt['Protocol'] != proto:
            continue
        if search_ip and search_ip not in (pkt['Source IP'] + pkt['Destination IP']):
            continue
        filtered.append({
            'Timestamp': pkt['Timestamp'],
            'Source IP': pkt['Source IP'],
            'Destination IP': pkt['Destination IP'],
            'Protocol': pkt['Protocol'],
            'Payload': pkt[view_key]
        })

    columns = [{"name": i, "id": i} for i in ['Timestamp', 'Source IP', 'Destination IP', 'Protocol', 'Payload']]
    return filtered, columns

@app.callback(
    Output("download-csv", "data"),
    Input("export-btn", "n_clicks"),
    State('protocol-filter', 'value'),
    State('search-ip', 'value'),
    State('payload-view', 'value'),
    prevent_initial_call=True
)
def export_csv(n_clicks, proto, search_ip, payload_view):
    view_key = 'Payload (ASCII)' if payload_view == 'ascii' else 'Payload (Hex)'
    filtered = []

    for pkt in packet_data:
        if proto != 'All' and pkt['Protocol'] != proto:
            continue
        if search_ip and search_ip not in (pkt['Source IP'] + pkt['Destination IP']):
            continue
        filtered.append({
            'Timestamp': pkt['Timestamp'],
            'Source IP': pkt['Source IP'],
            'Destination IP': pkt['Destination IP'],
            'Protocol': pkt['Protocol'],
            'Payload': pkt[view_key]
        })

    df = pd.DataFrame(filtered)
    return dcc.send_data_frame(df.to_csv, "packet_log.csv")

if __name__ == '__main__':
    app.run_server(debug=False, port=8050)

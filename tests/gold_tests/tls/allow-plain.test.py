'''
Test the allow-plain attribute of the ssl port
Clients sending non-tls request to ssl port should get passed to
non-tls processing in ATS if the allow-plain attibute is present
'''
#  Licensed to the Apache Software Foundation (ASF) under one
#  or more contributor license agreements.  See the NOTICE file
#  distributed with this work for additional information
#  regarding copyright ownership.  The ASF licenses this file
#  to you under the Apache License, Version 2.0 (the
#  "License"); you may not use this file except in compliance
#  with the License.  You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
#  Unless required by applicable law or agreed to in writing, software
#  distributed under the License is distributed on an "AS IS" BASIS,
#  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#  See the License for the specific language governing permissions and
#  limitations under the License.

import os

Test.Summary = '''
Test allow-plain attributed
'''

Test.ContinueOnFail = True

# Define default ATS
ts = Test.MakeATSProcess("ts", enable_tls=True)
server = Test.MakeOriginServer("server")

testName = "VIA"

# We only need one transaction as only the VIA header will be checked.
request_header = {"headers": "GET / HTTP/1.1\r\nHost: www.example.com\r\n\r\n", "timestamp": "1469733493.993", "body": ""}
response_header = {"headers": "HTTP/1.1 200 OK\r\nConnection: close\r\n\r\n", "timestamp": "1469733493.993", "body": ""}
server.addResponse("sessionlog.json", request_header, response_header)

ts.addDefaultSSLFiles()

ts.Disk.records_config.update({
    'proxy.config.http.server_ports': '{0}:ssl:allow-plain'.format(ts.Variables.ssl_port),
    'proxy.config.ssl.server.cert.path': '{0}'.format(ts.Variables.SSLDir),
    'proxy.config.ssl.server.private_key.path': '{0}'.format(ts.Variables.SSLDir),
    'proxy.config.diags.debug.enabled': 0,
    'proxy.config.diags.debug.tags': 'ssl|http',
})

ts.Disk.remap_config.AddLine(
    'map / http://127.0.0.1:{0}'.format(server.Variables.Port)
)

ts.Disk.ssl_multicert_config.AddLine(
    'dest_ip=* ssl_cert_name=server.pem ssl_key_name=server.key'
)

# TLS curl should work of course
tr = Test.AddTestRun()
# Wait for the micro server
tr.Processes.Default.StartBefore(server, ready=When.PortOpen(server.Variables.Port))
# Delay on readiness of our ssl ports
tr.Processes.Default.StartBefore(Test.Processes.ts)

tr.Processes.Default.Command = 'curl -k --verbose --ipv4 --http1.1 --resolve www.example.com:{}:127.0.0.1 https://www.example.com:{}'.format(
    ts.Variables.ssl_port, ts.Variables.ssl_port)
tr.Processes.Default.ReturnCode = 0
tr.StillRunningAfter = server
tr.StillRunningAfter = ts
tr.Processes.Default.Streams.all = Testers.ContainsExpression("TLS", "Should negiotiate TLS")

# non-TLS curl should also work to the same port
tr2 = Test.AddTestRun()
tr2.Processes.Default.Command = 'curl --verbose --ipv4 --http1.1 --resolve www.example.com:{}:127.0.0.1 http://www.example.com:{}'.format(
    ts.Variables.ssl_port, ts.Variables.ssl_port)
tr2.Processes.Default.ReturnCode = 0
tr2.StillRunningAfter = server
tr2.StillRunningAfter = ts
tr2.Processes.Default.Streams.all = Testers.ExcludesExpression("TLS", "Should not negiotiate TLS")

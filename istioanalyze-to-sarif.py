import json

# Lê a saída do Istio Analyzer (substitua isso pelo comando real)
istio_output = """
Error [IST0106] (Gateway default/malicious-gateway temp.yaml:1) Schema validation error: invalid protocol "", supported protocols are HTTP, HTTP2, GRPC, GRPC-WEB, MONGO, REDIS, MYSQL, TCP
Error [IST0128] (DestinationRule default/malicious-dest-rule temp.yaml:42) DestinationRule default/malicious-dest-rule in namespace default has TLS mode set to SIMPLE but no caCertificates are set to validate server identity for host: malicious-service.default.svc.cluster.local
Warning [IST0133] (ServiceEntry default/malicious-svc-entry temp.yaml:53) Schema validation warning: addresses are required for ports serving TCP (or unset) protocol
Warning [IST0134] (ServiceEntry default/malicious-svc-entry temp.yaml:62) ServiceEntry addresses are required for this protocol.
Warning [IST0134] (ServiceEntry default/malicious-svc-entry temp.yaml:64) ServiceEntry addresses are required for this protocol.
Info [IST0102] (Namespace default) The namespace is not enabled for Istio injection. Run 'kubectl label namespace default istio-injection=enabled' to enable it, or 'kubectl label namespace default istio-injection=disabled' to explicitly mark it as not needing injection.
Error: Analyzers found issues when analyzing namespace: default.
"""

# Divida a saída em linhas
istio_lines = istio_output.strip().split('\n')

# Estrutura SARIF básica
sarif_data = {
    "version": "2.1.0",
    "runs": [
        {
            "tool": {
                "driver": {
                    "name": "Istio Analyzer",
                    "version": "1.16"  # Substitua pela versão do Istio Analyzer, se aplicável
                }
            },
            "results": []
        }
    ]
}

# Processa cada linha da saída do Istio Analyzer
for line in istio_lines:
    parts = line.split(None, 4)  # Aumente para 4 para lidar com a saída completa
    if len(parts) >= 4:
        level, rule_id, location, message = parts[0], parts[1], parts[2], " ".join(parts[3:])
        # Construa um resultado SARIF com base na linha
        sarif_result = {
            "ruleId": rule_id,
            "level": level.lower(),
            "message": message.strip(),
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {
                            "uri": location.split()[1] if len(location.split()) > 1 else "",
                            "uriBaseId": "%SRCROOT%"
                        },
                        "region": {
                            "startLine": int(location.split(':')[1]) if len(location.split(':')) > 1 else 0
                        }
                    }
                }
            ]
        }
        sarif_data["runs"][0]["results"].append(sarif_result)

# Converta os dados SARIF em JSON
sarif_json = json.dumps(sarif_data, indent=2)

# Salve os dados em um arquivo SARIF
with open("istio_results.sarif", "w") as sarif_file:
    sarif_file.write(sarif_json)

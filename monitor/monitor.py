#!/usr/bin/env python3
import requests
import time
import json
from datetime import datetime, timedelta
from elasticsearch import Elasticsearch

# Configuración
ES_HOST = "http://elasticsearch:9200"
SHUFFLE_WEBHOOK = "http://shuffle-backend:5001/api/v1/hooks/webhook_4050638a-30ff-4cb5-b51a-1a00ac14d914"
CHECK_INTERVAL = 60  # Revisar cada 60 segundos
ALERT_THRESHOLD = 5  # Mínimo de eventos para alertar
TIME_WINDOW_MINUTES = 5  # Ventana de tiempo

# Conectar a Elasticsearch
es = Elasticsearch([ES_HOST])

# Almacenar última vez que se envió alerta
last_alert_time = None

print(f"[INFO] Monitor iniciado - Revisando cada {CHECK_INTERVAL} segundos")
print(f"[INFO] Conectando a Elasticsearch: {ES_HOST}")
print(f"[INFO] Webhook Shuffle: {SHUFFLE_WEBHOOK}")

def check_ssh_attacks():
    global last_alert_time
    
    # Calcular ventana de tiempo
    now = datetime.now()
    time_from = now - timedelta(minutes=TIME_WINDOW_MINUTES)
    
    # Query para buscar intentos fallidos de SSH
    query = {
    "query": {
        "bool": {
            "must": [
                {
                    "range": {
                        "@timestamp": {
                            "gte": time_from.isoformat(),
                            "lte": now.isoformat()
                        }
                    }
                },
                {
                    "bool": {
                        "should": [
                            {"match_phrase": {"message": "Failed password"}},
                            {"match_phrase": {"message": "authentication failure"}},
                            {"match_phrase": {"message": "Invalid user"}},
                            {"match_phrase": {"message": "Connection closed by authenticating user"}}
                        ],
                        "minimum_should_match": 1
                    }
                },
                # NUEVO: Filtrar solo logs del contenedor victim-ssh
                {
                    "bool": {
                        "should": [
                            {"match": {"container.name": "victim-ssh"}},
                            {"match": {"host.name": "victim-ssh"}}
                        ],
                        "minimum_should_match": 1
                    }
                }
            ]
        }
    }
}
    
    try:
        # Buscar en índices de Filebeat
        result = es.search(index="filebeat-*", body=query, size=100)
        hits_count = result['hits']['total']['value']
        
        print(f"[INFO] {now.strftime('%Y-%m-%d %H:%M:%S')} - Eventos detectados: {hits_count}")
        
        # Si hay suficientes eventos y no hemos alertado recientemente
        if hits_count >= ALERT_THRESHOLD:
            # Evitar alertas duplicadas (cooldown de 5 minutos)
            if last_alert_time is None or (now - last_alert_time).total_seconds() > 300:
                send_alert_to_shuffle(hits_count, result['hits']['hits'])
                last_alert_time = now
            else:
                print(f"[INFO] Alerta ya enviada hace {int((now - last_alert_time).total_seconds())} segundos. Esperando...")
        
    except Exception as e:
        print(f"[ERROR] Error al consultar Elasticsearch: {e}")

def send_alert_to_shuffle(event_count, events):
    """Envía la alerta a Shuffle via webhook"""
    
    # Extraer información relevante de los eventos
    sample_events = []
    for event in events[:5]:  # Solo los primeros 5
        source = event['_source']
        sample_events.append({
            'timestamp': source.get('@timestamp'),
            'message': source.get('message', '')[:200],  # Primeros 200 caracteres
            'host': source.get('host', {}).get('name', 'unknown')
        })
    
    # Payload para Shuffle
    payload = {
        'alert_type': 'SSH Brute Force Detected',
        'severity': 'HIGH',
        'event_count': event_count,
        'time_window': f'{TIME_WINDOW_MINUTES} minutes',
        'timestamp': datetime.now().isoformat(),
        'description': f'Detectados {event_count} intentos fallidos de SSH en los últimos {TIME_WINDOW_MINUTES} minutos',
        'sample_events': sample_events,
        'recommended_actions': [
            'Revisar logs en Kibana',
            'Verificar IP de origen',
            'Considerar bloqueo temporal de IP',
            'Evaluar si es ataque legítimo o falso positivo'
        ]
    }
    
    try:
        print(f"[ALERT] Enviando alerta a Shuffle - {event_count} eventos detectados")
        response = requests.post(SHUFFLE_WEBHOOK, json=payload, timeout=10)
        
        if response.status_code in [200, 201]:
            print(f"[SUCCESS] Alerta enviada exitosamente a Shuffle")
            print(f"[SUCCESS] Respuesta: {response.text}")
        else:
            print(f"[ERROR] Error al enviar a Shuffle: {response.status_code} - {response.text}")
    
    except Exception as e:
        print(f"[ERROR] Excepción al enviar alerta a Shuffle: {e}")

# Loop principal
if __name__ == "__main__":
    print("[INFO] Iniciando monitoreo...")
    
    while True:
        try:
            check_ssh_attacks()
        except KeyboardInterrupt:
            print("\n[INFO] Monitor detenido por el usuario")
            break
        except Exception as e:
            print(f"[ERROR] Error inesperado: {e}")
        
        time.sleep(CHECK_INTERVAL)

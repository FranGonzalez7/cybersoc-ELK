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
print(f"[INFO] Horario laboral configurado: 09:00 - 14:30")

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
                    # Filtrar solo logs del contenedor victim-ssh
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
        
        print(f"[INFO] {now.strftime('%Y-%m-%d %H:%M:%S')} - Eventos de brute force detectados: {hits_count}")
        
        # Si hay suficientes eventos y no hemos alertado recientemente
        if hits_count >= ALERT_THRESHOLD:
            # Evitar alertas duplicadas (cooldown de 5 minutos)
            if last_alert_time is None or (now - last_alert_time).total_seconds() > 300:
                send_alert_to_shuffle(hits_count, result['hits']['hits'])
                last_alert_time = now
            else:
                print(f"[INFO] Alerta de brute force ya enviada hace {int((now - last_alert_time).total_seconds())} segundos. Esperando...")
        
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

def check_successful_login_after_failures():
    """Detecta logins exitosos después de intentos fallidos"""
    
    now = datetime.now()
    time_from = now - timedelta(minutes=10)  # Ventana de 10 minutos
    
    # Primero, buscar logins exitosos
    query_success = {
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
                        "match_phrase": {"message": "Accepted password"}
                    },
                    {
                        "match": {"container.name": "victim-ssh"}
                    }
                ]
            }
        }
    }
    
    try:
        success_result = es.search(index="filebeat-*", body=query_success, size=10)
        
        if success_result['hits']['total']['value'] > 0:
            print(f"[INFO] Detectado {success_result['hits']['total']['value']} login(s) exitoso(s)")
            
            # Para cada login exitoso, verificar si hubo fallos previos
            for hit in success_result['hits']['hits']:
                message = hit['_source'].get('message', '')
                timestamp = hit['_source'].get('@timestamp')
                
                # Buscar intentos fallidos en los 5 minutos previos al login exitoso
                login_time = datetime.fromisoformat(timestamp.replace('Z', '+00:00'))
                time_before_login = login_time - timedelta(minutes=5)
                
                query_failures = {
                    "query": {
                        "bool": {
                            "must": [
                                {
                                    "range": {
                                        "@timestamp": {
                                            "gte": time_before_login.isoformat(),
                                            "lt": login_time.isoformat()
                                        }
                                    }
                                },
                                {
                                    "match_phrase": {"message": "Failed password"}
                                },
                                {
                                    "match": {"container.name": "victim-ssh"}
                                }
                            ]
                        }
                    }
                }
                
                failures_result = es.search(index="filebeat-*", body=query_failures, size=100)
                failed_count = failures_result['hits']['total']['value']
                
                if failed_count >= 3:  # Si hubo 3 o más intentos fallidos antes
                    send_compromised_alert(failed_count, message, failures_result['hits']['hits'][:5])
                    break  # Solo alertar una vez
    
    except Exception as e:
        print(f"[ERROR] Error al verificar logins exitosos: {e}")

def send_compromised_alert(failed_attempts, success_message, failure_events):
    """Envía alerta de cuenta potencialmente comprometida"""
    
    sample_failures = []
    for event in failure_events:
        source = event['_source']
        sample_failures.append({
            'timestamp': source.get('@timestamp'),
            'message': source.get('message', '')[:200]
        })
    
    payload = {
        'alert_type': 'SSH Account Compromised',
        'severity': 'CRITICAL',
        'failed_attempts': failed_attempts,
        'success_login': success_message,
        'timestamp': datetime.now().isoformat(),
        'description': f'¡ALERTA CRÍTICA! Login SSH exitoso después de {failed_attempts} intentos fallidos. Posible compromiso de cuenta.',
        'sample_failures': sample_failures,
        'recommended_actions': [
            'URGENTE: Bloquear IP de origen inmediatamente',
            'Cambiar contraseña del usuario afectado',
            'Revisar actividad del usuario tras el login',
            'Verificar si hay exfiltración de datos',
            'Contactar al usuario legítimo para confirmar actividad'
        ]
    }
    
    try:
        print(f"[CRITICAL] ¡CUENTA COMPROMETIDA! Login exitoso tras {failed_attempts} intentos fallidos")
        response = requests.post(SHUFFLE_WEBHOOK, json=payload, timeout=10)
        
        if response.status_code in [200, 201]:
            print(f"[SUCCESS] Alerta CRÍTICA enviada a Shuffle")
        else:
            print(f"[ERROR] Error al enviar alerta crítica: {response.status_code}")
    
    except Exception as e:
        print(f"[ERROR] Excepción al enviar alerta: {e}")

def check_outside_business_hours():
    """Detecta conexiones SSH fuera del horario laboral (09:00-14:30)"""
    
    now = datetime.now()
    current_hour = now.hour
    current_minute = now.minute
    current_total_minutes = current_hour * 60 + current_minute
    
    # Horario laboral: 09:00 (540 min) a 14:30 (870 min)
    BUSINESS_START = 9 * 60  # 540 minutos
    BUSINESS_END = 14 * 60 + 30  # 870 minutos
    
    # Solo revisar si estamos fuera de horario
    if BUSINESS_START <= current_total_minutes <= BUSINESS_END:
        return  # Estamos en horario laboral, no hacer nada
    
    time_from = now - timedelta(minutes=TIME_WINDOW_MINUTES)
    
    # Buscar conexiones SSH (exitosas o fallidas)
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
                                {"match_phrase": {"message": "Accepted password"}},
                                {"match_phrase": {"message": "Failed password"}},
                                {"match_phrase": {"message": "Connection closed by authenticating user"}}
                            ],
                            "minimum_should_match": 1
                        }
                    },
                    {
                        "match": {"container.name": "victim-ssh"}
                    }
                ]
            }
        }
    }
    
    try:
        result = es.search(index="filebeat-*", body=query, size=50)
        hits_count = result['hits']['total']['value']
        
        if hits_count > 0:
            print(f"[WARNING] Actividad SSH fuera de horario: {hits_count} eventos")
            send_outside_hours_alert(hits_count, now, result['hits']['hits'][:5])
    
    except Exception as e:
        print(f"[ERROR] Error al verificar horario: {e}")

def send_outside_hours_alert(event_count, detection_time, events):
    """Envía alerta de actividad fuera de horario"""
    
    sample_events = []
    for event in events:
        source = event['_source']
        sample_events.append({
            'timestamp': source.get('@timestamp'),
            'message': source.get('message', '')[:200],
        })
    
    payload = {
        'alert_type': 'SSH Activity Outside Business Hours',
        'severity': 'MEDIUM',
        'event_count': event_count,
        'detection_time': detection_time.strftime('%Y-%m-%d %H:%M:%S'),
        'business_hours': '09:00 - 14:30',
        'timestamp': detection_time.isoformat(),
        'description': f'Detectada actividad SSH fuera del horario laboral (09:00-14:30). {event_count} eventos registrados.',
        'sample_events': sample_events,
        'recommended_actions': [
            'Verificar si es actividad autorizada (mantenimiento, administrador)',
            'Identificar usuario y justificación del acceso',
            'Revisar qué comandos se ejecutaron durante el acceso',
            'Si no está autorizado, investigar como posible compromiso'
        ]
    }
    
    try:
        print(f"[ALERT] Actividad fuera de horario detectada - {event_count} eventos a las {detection_time.strftime('%H:%M')}")
        response = requests.post(SHUFFLE_WEBHOOK, json=payload, timeout=10)
        
        if response.status_code in [200, 201]:
            print(f"[SUCCESS] Alerta de horario enviada a Shuffle")
        else:
            print(f"[ERROR] Error al enviar alerta: {response.status_code}")
    
    except Exception as e:
        print(f"[ERROR] Excepción al enviar alerta: {e}")

# Loop principal
if __name__ == "__main__":
    print("[INFO] Iniciando monitoreo...")
    
    while True:
        try:
            check_ssh_attacks()
            check_successful_login_after_failures()
            check_outside_business_hours()
        except KeyboardInterrupt:
            print("\n[INFO] Monitor detenido por el usuario")
            break
        except Exception as e:
            print(f"[ERROR] Error inesperado: {e}")
        
        time.sleep(CHECK_INTERVAL)
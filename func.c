#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// Definición de la estructura IPInfo
typedef struct {
    char ip[16];
    int intentos;
    int fallidos;
} IPInfo;

/**
 * @brief Verifica si el archivo tiene la extensión .txt.
 * 
 * @param filename Nombre del archivo.
 * @return 1 si el archivo tiene extensión .txt, 0 en caso contrario.
 */
int verificar_extension(const char *filename) {
    const char *ext = strrchr(filename, '.');
    return (ext && strcmp(ext, ".txt") == 0);
}

/**
 * @brief Busca una IP en el arreglo y devuelve su índice.
 * 
 * @param ip_list Arreglo de estructuras IPInfo.
 * @param ip_count Número total de IPs analizadas.
 * @param ip Dirección IP a buscar.
 * @return Índice de la IP en el arreglo, o -1 si no se encuentra.
 */
int buscar_ip(IPInfo *ip_list, int ip_count, const char *ip) {
    for (int i = 0; i < ip_count; i++) {
        if (strcmp(ip_list[i].ip, ip) == 0) {
            return i;
        }
    }
    return -1;
}

/**
 * @brief Lee los registros de un archivo de logs y analiza los intentos por IP.
 * 
 * @param filename Nombre del archivo de logs.
 * @param ip_list Puntero al arreglo de estructuras IPInfo.
 * @param ip_count Puntero al número total de IPs analizadas.
 * @return 1 si la operación fue exitosa, 0 en caso de error.
 */
int leer_logs(const char *filename, IPInfo **ip_list, int *ip_count) {
    // Verificar que el archivo tenga extensión .txt
    if (!verificar_extension(filename)) {
        fprintf(stderr, "Error: El archivo %s no tiene extensión .txt.\n", filename);
        return 0;
    }

    FILE *file = fopen(filename, "r");
    if (!file) {
        fprintf(stderr, "Error: No se pudo abrir el archivo %s.\n", filename);
        return 0;
    }

    char line[512]; // Aumentado tamaño por seguridad
    int count = 0;
    IPInfo *list = NULL;

    while (fgets(line, sizeof(line), file)) {
        // Buscar las partes relevantes de la línea
        char *ip_ptr = strstr(line, "IP: ");
        char *status_ptr = strstr(line, "Status: ");

        // Si no se encuentran ambas, la línea no es válida
        if (!ip_ptr || !status_ptr) {
            fprintf(stderr, "Advertencia: Línea malformada en el archivo de logs: %s", line);
            continue;
        }

        ip_ptr += 4;      // Saltar "IP: "
        status_ptr += 8;  // Saltar "Status: "

        // Extraer IP y Status
        char ip[16], status[10];
        if (sscanf(ip_ptr, "%15s", ip) != 1 || sscanf(status_ptr, "%9s", status) != 1) {
            fprintf(stderr, "Advertencia: No se pudo extraer IP o estado en la línea: %s", line);
            continue;
        }

        // Buscar IP existente
        int index = buscar_ip(list, count, ip);
        if (index == -1) {
            // Nueva IP: agregar al arreglo
            list = realloc(list, (count + 1) * sizeof(IPInfo));
            if (!list) {
                fprintf(stderr, "Error: No se pudo asignar memoria.\n");
                fclose(file);
                return 0;
            }
            strcpy(list[count].ip, ip);
            list[count].intentos = 1;
            list[count].fallidos = (strcmp(status, "FAILED") == 0) ? 1 : 0;
            count++;
        } else {
            // IP ya existente: actualizar intentos
            list[index].intentos++;
            if (strcmp(status, "FAILED") == 0) {
                list[index].fallidos++;
            }
        }
    }

    fclose(file);
    *ip_list = list;
    *ip_count = count;
    return 1;
}

/**
 * @brief Muestra un resumen de los intentos por IP y detecta IPs sospechosas.
 * 
 * @param ip_list Arreglo de estructuras IPInfo.
 * @param ip_count Número total de IPs analizadas.
 */
void mostrar_resumen(IPInfo *ip_list, int ip_count) {
    printf("Resumen de intentos por IP:\n");
    for (int i = 0; i < ip_count; i++) {
        printf("IP: %s - %d intentos", ip_list[i].ip, ip_list[i].intentos);
        if (ip_list[i].fallidos > 3) {
            printf(" [Sospechosa]");
        }
        printf("\n");
    }
}

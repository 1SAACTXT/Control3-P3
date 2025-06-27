#include <stdio.h>
#include <stdlib.h>
#include "func.h"

/**
 * @brief Programa principal para analizar uno o más archivos de logs.
 * 
 * Este programa lee uno o más archivos de logs, analiza los intentos de acceso por IP y detecta IPs sospechosas.
 * 
 * @param argc Número de argumentos de línea de comandos.
 * @param argv Arreglo de argumentos de línea de comandos.
 *             Los argumentos deben ser los nombres de los archivos de logs.
 * @return 0 si la ejecución fue exitosa, 1 en caso de error.
 */
int main(int argc, char *argv[]) {
    // Validar argumentos de entrada
    if (argc < 2) {
        printf("Uso: %s <archivo_de_logs1> [archivo_de_logs2 ...]\n", argv[0]);
        return 1;
    }

    for (int file_index = 1; file_index < argc; file_index++) {
        const char *log_file = argv[file_index];
        IPInfo *ip_list = NULL;
        int ip_count = 0;

        printf("\nAnalizando archivo: %s\n", log_file);

        // Leer logs y analizar intentos por IP
        if (!leer_logs(log_file, &ip_list, &ip_count)) {
            printf("Error al leer el archivo de logs: %s\n", log_file);
            continue;
        }

        // Mostrar resumen de resultados
        mostrar_resumen(ip_list, ip_count);

        // Liberar memoria
        free(ip_list);
    }

    return 0;
}
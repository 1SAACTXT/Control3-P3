#ifndef FUNC_H
#define FUNC_H

/**
 * @brief Estructura para almacenar información de intentos por IP.
 */
typedef struct {
    char ip[16];    /**< Dirección IP. */
    int intentos;   /**< Número de intentos. */
    int fallidos;   /**< Número de intentos fallidos. */
} IPInfo;

/**
 * @brief Verifica si el archivo tiene la extensión .txt.
 * 
 * @param filename Nombre del archivo.
 * @return 1 si el archivo tiene extensión .txt, 0 en caso contrario.
 */
int verificar_extension(const char *filename);

/**
 * @brief Busca una IP en el arreglo y devuelve su índice.
 * 
 * @param ip_list Arreglo de estructuras IPInfo.
 * @param ip_count Número total de IPs analizadas.
 * @param ip Dirección IP a buscar.
 * @return Índice de la IP en el arreglo, o -1 si no se encuentra.
 */
int buscar_ip(IPInfo *ip_list, int ip_count, const char *ip);

/**
 * @brief Lee los registros de un archivo de logs y analiza los intentos por IP.
 * 
 * @param filename Nombre del archivo de logs.
 * @param ip_list Puntero al arreglo de estructuras IPInfo.
 * @param ip_count Puntero al número total de IPs analizadas.
 * @return 1 si la operación fue exitosa, 0 en caso de error.
 */
int leer_logs(const char *filename, IPInfo **ip_list, int *ip_count);

/**
 * @brief Muestra un resumen de los intentos por IP y detecta IPs sospechosas.
 * 
 * @param ip_list Arreglo de estructuras IPInfo.
 * @param ip_count Número total de IPs analizadas.
 */
void mostrar_resumen(IPInfo *ip_list, int ip_count);

#endif
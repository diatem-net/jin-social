<?php

/**
 * Jin Framework
 * Diatem
 */

namespace Jin2\Social\Google\Plus;

use Jin2\Com\Curl;

/**
 * Facilite l'utilisation de l'API Google+.
 */
class GooglePlus
{

  /**
   * @var string Google+ SERVER_KEY
   */
  protected $server_key;

  /**
   * @var boolean Debug mode
   */
  protected $debug_mode;

  /**
   * url de l'API Google+
   */
  const GOOGLEPLUS_API_URL = 'https://www.googleapis.com/plus/v1/';

  /**
   * Constructeur
   *
   * @param string $server_key       Clé serveur (à créer sur https://console.developers.google.com/apis/credentials)
   * @param string $debug_mode       (optional) Activer le mode debug
   */
  public function __construct($server_key, $debug_mode = false)
  {
    $this->server_key  = $server_key;
    $this->debug_mode  = $debug_mode;
  }

  /**
   * Effectue une requête directe sur l'API
   *
   * @param  string $query        Requête
   * @param  array  $params       (optional) Paramètres
   * @return array                Tableau de données
   */
  public function query($query, $params = array())
  {
    $curl = new Curl();
    $params['key'] = $this->server_key;
    $result = json_decode($curl->call(self::GOOGLEPLUS_API_URL . trim($query, '/') . '?' . http_build_query($params), array(), 'GET', true), true);
    if(!isset($result['error'])) {
      return $result;
    }
    return $this->debug_mode ? $result['error']['message'] : null;
  }

  /**
   * Retourne la liste des dernières activités d'un utilisateur
   *
   * @param  string $user_id      Identifiant de l'utilisateur
   * @param  int $count           (optional) Nombre max de résultats (Défault: 100)
   * @return array                Tableau d'activités
   */
  public function getLastActivitiesFromUser($user_id, $count = 100)
  {
    return $this->query('/people/'.$user_id.'/activities/public', array(
      'count' => $count
    ));
  }

}
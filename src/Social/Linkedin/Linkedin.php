<?php

/**
 * Jin Framework
 * Diatem
 */

namespace Jin2\Social\Linkedin;

use Jin2\Com\Curl;

/**
 * Méthodes d'implémentation de l'API LinkedIn.
 *
 * @see https://developer.linkedin.com/
 */
class LinkedIn
{

  /**
   * @var string  LinkedIn CLIENT_ID
   */
  protected $client_id;

  /**
   * @var string  LinkedIn ACCESS_TOKEN
   */
  protected $access_token;

  /**
   * @var boolean Debug mode
   */
  protected $debug_mode;

  /**
   * url de l'API LinkedIn
   */
  const LINKEDIN_API_URL = 'https://api.linkedin.com/v1/';

  /**
   * Constructeur
   *
   * @param string $client_id      Identifiant de l'application
   * @param string $access_token   Token d'accès
   * @param string $debug_mode     (optional) Activer le mode debug
   */
  public function __construct($client_id, $access_token, $debug_mode = false)
  {
    $this->client_id = $client_id;
    $this->access_token = $access_token;
    $this->debug_mode = $debug_mode;
  }

  /**
   * Génère un code d'autorisation, nécessaire pour la génération d'un token d'accès
   *
   * @param  string $client_id     Identifiant de l'application
   * @param  string $redirect_uri  URL de redirection
   * @param  string $state         Chaîne aléatoire à vérifier après la redirection
   * @param  string $scope         (optional) Degrés d'authorisation dont l'application à besoin (Défault : r_basicprofile)
   * @return string                Token d'accès, valable 60 jours
   */
  public static function generateAuthCode($client_id, $redirect_uri, $state, $scope = 'r_basicprofile rw_company_admin')
  {
    $params = array(
      'response_type' => 'code',
      'client_id'     => $client_id,
      'redirect_uri'  => $redirect_uri,
      'state'         => $state,
      'scope'         => $scope
    );
    header('location:https://www.linkedin.com/uas/oauth2/authorization?' . http_build_query($params));
    die;
  }

  /**
   * Génère un token d'accès
   *
   * @param  string $code          Code d'authentification généré par LinkedIn::generateAuthCode()
   * @param  string $redirect_uri  URL de redirection utilisée lors
   * @param  string $client_id     Identifiant de l'application
   * @param  string $client_secret Clé secrète de l'application
   * @return string                Token d'accès, valable 60 jours
   */
  public static function generateToken($code, $redirect_uri, $client_id, $client_secret)
  {
    $curl = new Curl();
    $params = array(
      'grant_type'    => 'authorization_code',
      'code'          => $code,
      'redirect_uri'  => $redirect_uri,
      'client_id'     => $client_id,
      'client_secret' => $client_secret
    );
    $result = json_decode($curl->call('https://www.linkedin.com/uas/oauth2/accessToken?' . http_build_query($params), array(), 'POST', true), true);
    return $result;
  }

  /**
   * Effectue une requête directe sur l'API
   *
   * @param  string $query         Requête
   * @param  array  $params        (optional) Paramètres
   * @return array                 Tableau de données
   */
  public function query($query, $params = array())
  {
    $curl = new Curl();
    $params['oauth2_access_token'] = $this->access_token;
    $params['format'] = 'json';
    $result = json_decode($curl->call(self::LINKEDIN_API_URL . trim($query, '/') . '?' . http_build_query($params), array(), 'GET', true), true);
    if(isset($result['errorCode'])) {
      return $this->debug_mode ? $result['message'] : null;
    }
    return $result['values'];
  }

  /**
   * Retourne les derniers posts publiés sur la page d'une entreprise
   *
   * @param string  $company_id   Nom de l'entreprise
   * @param integer $count        (optional) Nombre de posts à retourner (Défault : 100)
   * @return array                Tableau de posts
   */
  public function getLastUpdatesFromCompany($company_id, $count = 100)
  {
    return $this->query('companies/'.$company_id.'/updates', array(
      'count' => $count
    ));
  }

}
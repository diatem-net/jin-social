<?php

/**
 * Jin Framework
 * Diatem
 */

namespace Jin2\Social\Jasig\CAS;

use \phpCAS as PhpCAS;

/**
 * Gestion de l'authentification unique avec un serveur CAS de Jasig
 *
 * @see https://wiki.jasig.org/display/CASC/phpCAS
 */
class CASSSO
{

  protected static $host;
  protected static $port;
  protected static $context;
  protected static $ssl;
  protected static $debugging;
  protected static $serviceId;
  protected static $initialized;

  /**
   * Configure l'accès au serveur CAS. Nécessaire pour que les méthodes de connexion puissent fonctionner correctement
   *
   * @param string  $host       Url du serveur CAS
   * @param integer $port       Port du serveur CAS
   * @param string  $serviceId  ID du service (pour CAS)
   * @param string  $context    Contexte, ou namespace
   * @param boolean $ssl        (optional) SSL activé (true par défaut)
   * @param boolean $debugging  (optional) Mode debug activé (false par défaut)
   */
  public static function configure($host, $port, $serviceId, $context = 'cas', $ssl = true, $debugging = false)
  {
    self::$host = $host;
    self::$port = $port;
    self::$context = $context;
    self::$ssl = $ssl;
    self::$debugging = $debugging;
    self::$serviceId = $serviceId;

    if (self::$debugging) {
      PhpCAS::setDebug();
    }

    $serviceId = urlencode(self::$serviceId);
    PhpCAS::client(CAS_VERSION_2_0, self::$host, self::$port, self::$context);

    if (!self::$ssl) {
      PhpCAS::setNoCasServerValidation();
    }

    PhpCAS::setServerLoginURL(static::getBaseUrl().'login?service='.$serviceId);
    PhpCAS::setServerServiceValidateURL(static::getBaseUrl().'serviceValidate');
    PhpCAS::setServerProxyValidateURL(static::getBaseUrl().'proxyValidate');
    PhpCAS::setServerLogoutURL(static::getBaseUrl().'logout?destination='.$serviceId);

    self::$initialized = true;
  }

  /**
   * Initie une procédure de login
   */
  public static function login()
  {
    static::checkInit();
    PhpCAS::forceAuthentication();
  }

  /**
   * Déconnexion au serveur CAS (tous services)
   */
  public static function logout()
  {
    static::checkInit();
    PhpCAS::logout();
  }

  /**
   * Permet de savoir si l'utilisateur est connecté
   *
   * @return boolean
   */
  public static function isLogin()
  {
    static::checkInit();
    return PhpCAS::isAuthenticated();
  }

  /**
   * Vérifie l'authentification de l'utilisateur
   *
   * @return boolean
   */
  public static function checkAuthentification()
  {
    static::checkInit();

    if (static::isLogin()) {
      return PhpCAS::checkAuthentication();
    } else {
      return false;
    }
  }

  /**
   * Initie automatiquement une procédure de login si l'utilisateur n'est pas connecté
   */
  public static function autoLogin()
  {
    static::checkInit();
    if (!static::isLogin()) {
      static::login();
    }
  }

  /**
   * Retourne l'userID de CAS pour l'utilisateur connecté
   *
   * @return string
   */
  public static function getUser()
  {
    static::checkInit();
    return PhpCAS::getUser();
  }

  /**
   * Retourne la version utilisée de CAS
   *
   * @return string
   */
  public static function getCasVersion()
  {
    static::checkInit();
    return PhpCAS::getVersion();
  }

  /**
   * Construit l'url de connexion au serveur
   *
   * @return string
   */
  protected static function getBaseUrl()
  {
    $baseUrl = 'https://';
    if (!self::$ssl) {
      $baseUrl = 'http://';
    }
    $baseUrl .= sprintf('%s:%s/%s/', self::$host, self::$port, self::$context);
    return $baseUrl;
  }

  /**
   * Vérifie que la connexion à CAS est configurée avec CASSSO::configure. Génère une erreur dans le cas contraire
   *
   * @throws \Exception
   */
  protected static function checkInit()
  {
    if (!self::$initialized) {
      throw new \Exception('Vous devez appeler CASSSO::configure(...) avant toute autre opération d\'identification');
    }
  }

}

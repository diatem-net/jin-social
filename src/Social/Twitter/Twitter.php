<?php

/**
 * Jin Framework
 * Diatem
 */

namespace Jin2\Social\twitter;

use Abraham\TwitterOAuth;

/**
 * Facilite l'utilisation de l'API Twitter. Utilise la librairie twitteroauth d'Abraham Williams
 *
 * @see https://github.com/abraham/twitteroauth
 */
class Twitter
{

  /**
   * @var string  Twitter CONSUMER_KEY
   */
  protected $consumer_key;

  /**
   * @var string  Twitter CONSUMER_SECRET
   */
  protected $consumer_secret;

  /**
   * @var string  Twitter ACCESS TOKEN
   */
  protected $access_token;

  /**
   * @var string  Twitter ACCESS TOKEN SECRET
   */
  protected $access_token_secret;

  /**
   * @var TwitterOAuth Instance de la classe TwitterOAuth
   */
  protected $api;

  /**
   *
   * @var boolean Debug mode
   */
  protected $debug_mode;

  /**
   * Constructeur
   *
   * @param string $consumer_key         Paramétrage Twitter (Consumer Key)
   * @param string $consumer_secret    Paramétrage Twitter (Consumer secret)
   * @param string $access_token         Paramétrage Twitter (Access Token)
   * @param string $access_token_secret  Paramétrage Twitter (Access Token Secret)
   */
  public function __construct($consumer_key, $consumer_secret, $access_token, $access_token_secret, $debug_mode = false)
  {
    $this->consumer_key         = $consumer_key;
    $this->consumer_secret      = $consumer_secret;
    $this->access_token         = $access_token;
    $this->access_token_secret  = $access_token_secret;
    $this->debug_mode           = $debug_mode;

    $this->api = new TwitterOAuth($this->consumer_key, $this->consumer_secret, $this->access_token, $this->access_token_secret);
  }

  /**
   * Effectue une requête directe sur l'API
   *
   * @param  string $query         Requête
   * @param  array  $params        (optional) Paramètres
   * @return Array
   */
  public function query($query, $params = array())
  {
    $results = $this->api->get($query, $params);
    if(!isset($results->errors)) {
      return $results;
    } else {
      return $this->debug_mode ? $results->errors[0]->message : null;
    }
  }

  /**
   * Effectue une recherche sur tous les Tweets, dans un délai maximal de 21 jours et une limite de 100 résultats
   *
   * @param  string $query         Recherche à effectuer
   * @param  int $count            (optional) Nombre max de résultats (100 par défaut)
   * @return array
   * @throws \Exception
   */
  public function getLastTweetsFromQuery($query, $count = 100)
  {
    if($count > 100){
      throw new \Exception('100 résultats maximum supportés ('.$count.' souhaités)');
    }
    return $this->query('search/tweets', array(
      'q'      => $query,
      'count'  => $count
    ));
  }

  /**
   * Retourne la liste des derniers Tweets comportant un HashTag précis, dans un délai maximal de 21 jours et une limite de 100 résultats
   *
   * @param  string $hashtag     Hashtag à rechercher
   * @param  int $count         (optional) Nombre max de résultats (100 par défaut)
   * @return array
   * @throws \Exception
   */
  public function getLastTweetsContainingHashtag($hashtag, $count = 100)
  {
    return $this->getLastTweetsFromQuery(trim($hashtag, '#'), $count);
  }

  /**
   * Retourne la liste des derniers Tweets d'un utilisateur
   *
   * @param  string $screen_name   Nom de l'utilisateur
   * @param  int $with_replies     (optional) Inclure les réponses (false par défaut)
   * @param  int $with_rt          (optional) Inclure les retweets (false par défaut)
   * @param  int $count            (optional) Nombre max de résultats (100 par défaut, max 200)
   * @return Array
   * @throws \Exception
   */
  public function getLastTweetsFromUser($screen_name, $with_replies = false, $with_rt = false, $count = 100)
  {
    if($count > 200){
      throw new \Exception('200 résultats maximum supportés ('.$count.' souhaités)');
    }
    return $this->query('statuses/user_timeline', array(
      'screen_name'        => $screen_name,
      'count'              => $count,
      'exclude_replies'    => !$with_replies,
      'include_rts'        => $with_rt
    ));
  }

  /**
   * Retourne les userId des followers
   *
   * @return array
   */
  public function getFollowersUserIds()
  {
    return $this->query('followers/ids');
  }

}
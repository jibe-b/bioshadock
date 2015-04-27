/*jslint sub:true, browser: true, indent: 4, vars: true, nomen: true */

(function () {
  'use strict';


    function User($resource) {
        return $resource('/user/:uid', {}, {
            is_authenticated: {
                url: '/user/logged',
                method: 'GET',
                isArray: false,
                cache: false
            },
            authenticate: {
                url: '/user/bind',
                method: 'POST',
                isArray: false,
                cache: false
            },
            logout: {
                url: '/user/logout',
                method: 'GET',
                isArray: false,
                cache: false
            }
        });

    }

    function Container($resource) {
        return $resource('/container/:id', {}, {
            search: {
                url: '/container/search',
                method: 'POST',
                isArray: true,
                cache: false
            }
        });

    }

    function Config($resource) {
        return $resource('/config');

    }


  angular.module('bioshadock.resources', ['ngResource'])
      .factory('User', User)
      .factory('Container', Container)
      .factory('Config', Config)

}());

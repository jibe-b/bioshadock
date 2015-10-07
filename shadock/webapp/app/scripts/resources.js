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

    function Search($resource) {
        return $resource('/search', {}, {
            search: {
                url: '/search',
                method: 'GET',
                isArray: false,
                cache: false
            }
        });
    }

    function Container($resource) {
        return $resource('/container/:id', {}, {
            query_all: {
                url: '/container/all',
                method: 'GET',
                isArray: true,
                cache: false
            },
            create_new: {
                url: '/container/new',
                method: 'POST',
                isArray: false,
                cache: false
            },
            latest: {
                url: '/container/latest',
                method: 'GET',
                isArray: true,
                cache: false
            },
            search: {
                url: '/container/search',
                method: 'POST',
                isArray: true,
                cache: false
            },
            manifest: {
                url: '/container/manifest/:id',
                method: 'POST',
                isArray: false,
                cache: false
            },
            tags: {
                url: '/container/tags/:id',
                method: 'POST',
                isArray: false,
                cache: false
            },
            dockerFile: {
                url: '/container/dockerfile/:id',
                method: 'POST',
                isArray: false,
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
      .factory('Search', Search)

}());

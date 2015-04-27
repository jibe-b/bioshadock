/*global  angular:false */
/*jslint sub: true, browser: true, indent: 4, vars: true, nomen: true */
'use strict';

// Declare app level module which depends on filters, and services
var app = angular.module('bioshadock', ['bioshadock.resources', 'ngSanitize', 'ngCookies', 'ngRoute', 'ui.utils', 'ui.bootstrap', 'datatables', 'ui.codemirror'])
.config(function($routeProvider, $locationProvider) {
  $routeProvider
  .when('/', {
    templateUrl: 'views/welcome.html',
    controller: 'welcomeCtrl'
  })
  .when('/containers', {
    templateUrl: 'views/containers.html',
    controller: 'containersCtrl'
  })
  .when('/my/containers', {
    templateUrl: 'views/mycontainers.html',
    controller: 'mycontainersCtrl'
  })
  .when('/container/:path*', {
    templateUrl: 'views/container.html',
    controller: 'containerCtrl'
  })
  .when('/dockerfile/:path*', {
    templateUrl: 'views/dockerfile.html',
    controller: 'containerDockerFileCtrl'
  })
  .when('/login', {
    templateUrl: 'views/login.html',
    controller: 'loginCtrl'
  });

})
.factory('authInterceptor', function ($rootScope, $q, $window) {
  return {
    request: function (config) {
      config.headers = config.headers || {};
      if ($window.sessionStorage.token) {
        config.headers.Authorization = 'Bearer ' + $window.sessionStorage.token;
      }
      return config;
    },
    response: function (response) {
      if (response.status === 401) {
        // handle the case where the user is not authenticated
        location.replace('#/login');
        return;
      }
      return response || $q.when(response);
  },
  'responseError': function(rejection){
      if(rejection.status == 401) {
          // Route to #/login
          location.replace('#/login');
      }
      return $q.reject(rejection);
  }
  };
})
.config(['$httpProvider', function ($httpProvider){
    $httpProvider.interceptors.push('authInterceptor');
}])
.controller('welcomeCtrl',
    function ($scope, $route) {

})
.controller('containerCtrl',
    function ($scope, $route, $routeParams, $document, $http, Container, Config, Auth) {
        $scope.container_id = $routeParams.path;
        $scope.tag = 'latest'
        var user = Auth.getUser();
        $scope.get_container = function(){
            Container.get({'id': $scope.container_id}).$promise.then(function(data){
                $scope.container = data;

                var req = {
                 method: 'POST',
                 url: '/v2/token/',
                 headers: {
                   'Content-Type': 'application/json'
                 },
                 params: {
                     'account': user['id'],
                     'service': $scope.service,
                     'scope': 'repository:'+$scope.container_id+':pull'
                 }
                };

                $http(req).success(function(data, status, headers, config) {
                    Container.manifest({'id': $scope.container_id},{'token': data.token, 'tag': $scope.tag}).$promise.then(function(data){
                        $scope.manifest = data;
                    });
                    Container.tags({'id': $scope.container_id},{'token': data.token}).$promise.then(function(data){
                        $scope.tags = data.tags;
                    });
                });
            });
        };
        Config.get().$promise.then(function(config) {
            $scope.registry = config['registry'];
            $scope.service = config['service'];
            $scope.get_container();

        });

        $scope.go_to_dockerfile = function(){
            location.replace('#/dockerfile/'+$scope.container_id);
        }
})
.controller('containerDockerFileCtrl',
    function ($scope, $route, $routeParams, $document, Container, Config) {
        $scope.container_id = $routeParams.path;
        Config.get().$promise.then(function(config) {
            $scope.registry = config['registry'];

            Container.get({'id': $scope.container_id}).$promise.then(function(data){
                $scope.container = data;
            });
        });
        $scope.go_to_info = function(){
            location.replace('#/container/'+$scope.container_id);
        }
        $scope.update_dockerfile = function() {
            Container.dockerFile({'id': $scope.container_id},{'dockerfile': $scope.container.meta.Dockerfile}).$promise.then(function(data){
                $scope.msg = "New build requested after Dockerfile update";
            });
        }
})
.controller('mycontainersCtrl',
    function ($scope, $route, Container) {
        Container.query().$promise.then(function(data) {
            $scope.containers = data;
        });
        $scope.show_container = function(data) {
             location.replace('#/container/'+data.id);
        };
})
.controller('containersCtrl',
    function ($scope, $route, Container) {
        $scope.selected = undefined;
        $scope.get_containers = function(val) {
            return Container.search({},{'search': val}).$promise.then(function(data){
                return data.map(function(item){
                        return item.id;
                  });
            });
        }
        $scope.select = function(item, model, label) {
            Container.get({'id': item}).$promise.then(function(data){
                $scope.containers = [data];
            });
        };
        $scope.search = function() {
            Container.search({},{'search': $scope.selected}).$promise.then(function(data){
                $scope.containers = data;
            });
        }

        $scope.show_container = function(data) {
             location.replace('#/container/'+data.id);
        };

})
.controller('TaskModalInstanceCtrl', function ($scope, $modalInstance, items) {

  $scope.selectedtask = items;

  $scope.convert_timestamp_to_date = function(UNIX_timestamp){
    if(UNIX_timestamp=='' || UNIX_timestamp===null || UNIX_timestamp===undefined) { return '';}
    var a = new Date(UNIX_timestamp*1000);
    var months = ['Jan','Feb','Mar','Apr','May','Jun','Jul','Aug','Sep','Oct','Nov','Dec'];
    var year = a.getFullYear();
    var month = months[a.getMonth()];
    var date = a.getDate();
    var hour = a.getHours();
    var min = a.getMinutes();
    var sec = a.getSeconds();
    var time = date + ',' + month + ' ' + year + ' ' + hour + ':' + min + ':' + sec ;
    return time;
  }

  $scope.ok = function () {
    //$modalInstance.close($scope.selectedtask);
  };

  $scope.cancel = function () {
    $modalInstance.dismiss('cancel');
  };
})
.controller('userCtrl',
    function($scope, $rootScope, $routeParams, $log, $location, $window, Auth, User) {
        $scope.is_logged = false;

        $rootScope.$on('loginCtrl.login', function (event, user) {
           $scope.user = user;
           $scope.is_logged = true;
        });

        $scope.logout = function() {
            if($window.sessionStorage != null) {
                delete $window.sessionStorage.token;
            }
            Auth.setUser(null);
            $scope.user = null;
            $scope.is_logged = false;
            $location.path('/login');
        };

        User.is_authenticated().$promise.then(function(user) {
            if(user !== null && user['id'] !== undefined) {
                $scope.user = user;
                $scope.is_logged = true;
                Auth.setUser($scope.user);
            }
        });

})
.controller('loginCtrl',
    function ($scope, $rootScope, $route, $location, $window, Auth, User) {
        $scope.uid = "";
        $scope.password = "";
        $scope.authenticate = function() {
            User.authenticate({},{'uid':$scope.uid, 'password':$scope.password}).$promise.then(function(data){
                var user = data['user'];
                if($window.sessionStorage != null) {
                    $window.sessionStorage.token = data.token;
                }
                if(user['id'] !== undefined) {
                    Auth.setUser(user);
                    $rootScope.$broadcast('loginCtrl.login', user);
                    $location.path('/');
                }
                else{
                    $scope.msg = "Could not authenticate!";
                }
            }, function(data) {
                if($window.sessionStorage != null) {
                    delete $window.sessionStorage.token;
                }
                $scope.msg = "Could not authenticate!";
            });

        };
})
.service('Auth',
    function(){
        var user =null;
        return {
            getUser: function() {
                return user;
            },
            setUser: function(newUser) {
                user = newUser;
            },
            isConnected: function() {
                return !!user;
            }
        };
});

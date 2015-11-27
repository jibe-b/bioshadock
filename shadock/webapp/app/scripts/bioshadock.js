/*global  angular:false */
/*jslint sub: true, browser: true, indent: 4, vars: true, nomen: true */
'use strict';

// Declare app level module which depends on filters, and services
var app = angular.module('bioshadock', ['bioshadock.resources', 'ngSanitize', 'ngCookies', 'ngRoute', 'ui.utils', 'ui.bootstrap', 'datatables', 'ui.codemirror', 'xeditable'])
.config(function($routeProvider, $locationProvider) {
  $routeProvider
  .when('/', {
    templateUrl: 'views/welcome.html',
    controller: 'welcomeCtrl'
  })
  .when('/help', {
    templateUrl: 'views/help.html',
    controller: 'helpCtrl'
  })
  .when('/search', {
    templateUrl: 'views/search.html',
    controller: 'searchCtrl'
  })
  .when('/users', {
    templateUrl: 'views/users.html',
    controller: 'usersCtrl'
  })
  .when('/containers', {
    templateUrl: 'views/containers.html',
    controller: 'containersCtrl'
  })
  .when('/my/containers', {
    templateUrl: 'views/mycontainers.html',
    controller: 'mycontainersCtrl'
  })
  .when('/all/containers', {
    templateUrl: 'views/mycontainers.html',
    controller: 'allcontainersCtrl'
  })
  .when('/my/new', {
    templateUrl: 'views/newcontainer.html',
    controller: 'newcontainerCtrl'
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
  })
  .when('/user/:id', {
    templateUrl: 'views/user.html',
    controller: 'usermngtCtrl'
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
    function ($scope, $route, Config) {
    Config.get().$promise.then(function(config) {
        $scope.registry = config['registry'];
        $scope.service = config['service'];
        $scope.issuer = config['issuer'];
    });
})
.controller('helpCtrl',function ($scope) {
})
.controller('usersCtrl',
    function ($scope, $route, User) {
        User.query({}, function(data){
            $scope.users = data;
        });
        $scope.change_role = function(user){
                user.$save({'uid': user.id});
        };

})
.controller('searchCtrl',
    function ($scope, $route, $routeParams, Search) {
        Search.search({'q': decodeURIComponent($routeParams.q)}, function(data){
            $scope.hits = data.hits;
        });
})
.controller('newcontainerCtrl',
    function ($scope, $route, $routeParams, $http, Container, Auth) {
    var user = Auth.getUser();
    $scope.containerName = '';
    $scope.containerDescription = '';
    $scope.containerDockerfile = '';
    $scope.containerVisible = true;
    $scope.containerGit = '';

    $scope.cmOption = {
        lineNumbers: true,
        indentWithTabs: true,
        mode: 'docker'
      };

    $scope.create_container = function() {
        if($scope.containerName == '') {
            $scope.msg = "Missing or empty name";
            return;
        }
        if($scope.containerName.split('/').length==1) {
            $scope.msg = "Name must contain at least one '/' eg namespace/containername"
            return;
        }
        if($scope.containerDescription == '') {
            $scope.msg = "Missing or empty description";
            return;
        }
        if($scope.containerDockerfile == '' && $scope.containerGit == '') {
            $scope.msg = "Missing or empty Docker file or git repository, please fill one";
            return;
        }
        //Container.get({'id': $scope.containerName}).$promise.then(function(data){
        $http.get('/container/'+$scope.containerName).success(function(data){
            $scope.msg = "Name already exists";
        }).error(function(data, status, headers, config){
            if(status != 404) {
                $scope.msg = "Name already exists or cannot be used";
            }
            else {
                Container.create_new({},
                    {'name':  $scope.containerName,
                    'description': $scope.containerDescription,
                    'dockerfile': $scope.containerDockerfile,
                    'visible': $scope.containerVisible,
                    'git': $scope.containerGit
                    }).$promise.then(function(data){
                    location.replace('#/container/'+$scope.containerName);
                }, function(error) {
                    $scope.msg = error.statusText;
                });
            }
        });
        /*
        Container.create_new({},
            {'name':  $scope.containerName,
            'description': $scope.containerDescription,
            'dockerfile': $scope.containerDockerfile
            }).$promise.then(function(data){
            location.replace('#/container/'+$scope.containerName);
        }, function(error) {
            $scope.msg = error;
        });
        */
    }

})
.controller('containerCtrl',
    function ($scope, $route, $routeParams, $document, $http, $location, Container, Config, Auth) {
        $scope.container_id = $routeParams.path;
        $scope.msg = '';
        $scope.tag = 'latest'
        var user = Auth.getUser();
        $scope.user = user;
        $scope.show_save = false;
        $scope.newtag = '';
        $scope.newterm = '';

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
        };

        $scope.addtag = function(newtag) {
            if(newtag=='' ||  $scope.container.meta.tags.indexOf(newtag)>=0) { return;}
            $scope.container.meta.tags.push(newtag);
            $scope.show_save = true;
        }

        $scope.addterm = function(newterm) {
            if(newterm=='' ||  $scope.container.meta.terms.indexOf(newterm)>=0) { return;}
            $scope.container.meta.terms.push(newterm);
            $scope.show_save = true;
        }

        $scope.add_member_push = function(member) {
            if(member=='' ||  $scope.container.acl_push.members.indexOf(member)>=0) { return;}
            $scope.container.acl_push.members.push(member);
            $scope.container.acl_pull.members.push(member);
            $scope.show_save = true;
        }

        $scope.add_member_pull = function(member) {
            if(member=='' ||  $scope.container.acl_pull.members.indexOf(member)>=0) { return;}
            $scope.container.acl_pull.members.push(member);
            $scope.show_save = true;
        }

        $scope.delete_tag = function(elt) {
            var index =  $scope.container.meta.tags.indexOf(elt);
            if (index > -1) {
                 $scope.container.meta.tags.splice(index, 1);
                 $scope.show_save = true;
            }
        };

        $scope.delete_term = function(elt) {
            var index =  $scope.container.meta.terms.indexOf(elt);
            if (index > -1) {
                 $scope.container.meta.terms.splice(index, 1);
                 $scope.show_save = true;
            }
        };

        $scope.delete_member_pull = function(elt) {
            var index =  $scope.container.acl_pull.members.indexOf(elt);
            if (index > -1) {
                 $scope.container.acl_pull.members.splice(index, 1);
                 $scope.show_save = true;
            }
        };


        $scope.delete_member_push = function(elt) {
            var index =  $scope.container.acl_push.members.indexOf(elt);
            if (index > -1) {
                 $scope.container.acl_push.members.splice(index, 1);
                 $scope.show_save = true;
            }
        };

        $scope.delete_container = function(){
                var req = {
                 method: 'DELETE',
                 url: '/container/'+$scope.container_id,
                 headers: {
                   'Content-Type': 'application/json'
                 }
                };
                $http(req).success(function(data, status, headers, config) {
                    $location.path('/');
                });

        };

        $scope.proposesave = function(){
            $scope.show_save = true;
        };

        $scope.update_container = function(container){
            var req = {
             method: 'POST',
             url: '/container/'+$scope.container_id,
             headers: {
               'Content-Type': 'application/json'
             },
             data: container
            };
            $http(req).success(function(data, status, headers, config) {
            //container.$save({'id': container.id}).then(function(data){
                 $scope.msg = "Container updated";
                 $scope.show_save = false;
             });
        };

        $scope.elixir_versions = [];
        $scope.get_elixir_meta = function() {
            //$http.get('https://bio.tools/api/tool/BioCatalogue/phmmer').success(function(data){
            $http.get('https://bio.tools/api/tool/'+$scope.container.meta.elixir).success(function(data){
               var versions = [];
               for(var i=0;i<data.length;i++) {
                   versions.push({'url': 'https://bio.tools/api/tool/BioCatalogue/phmmer/'+data[i].version, 'version': data[i].version});
               }
               $scope.elixir_versions = versions;
            });


        };

        $scope.elixir = function(){
            $http.get('/container/elixir/'+$scope.container_id).success(function(data){
               $scope.msg = data.msg;
               if(data.elixir !== undefined) {
                 $scope.container.meta.elixir = data.elixir;
                 $scope.get_elixir_meta();
               }
            }).error(function(data){ $scope.msg = 'An error occured'; });
        };

        $scope.get_container = function(){
            //Container.get({'id': $scope.container_id}).$promise.then(function(data){
            $http.get('/container/'+$scope.container_id).success(function(data){
                $scope.container = data;
                if(user == null) { user = {'id': 'anonymous'}}
                var req = {
                 method: 'POST',
                 url: '/v2/token/',
                 headers: {
                   'Content-Type': 'application/json'
                 },
                 params: {
                     'account': user['id'],
                     'service': $scope.service,
                     'scope': 'repository:'+$scope.container_id+':manifest'
                 }
                };
                if($scope.container.meta.elixir !== undefined && $scope.container.meta.elixir!=null && $scope.container.meta.elixir!='') {
                    $scope.get_elixir_meta();
                }

                $http(req).success(function(data, status, headers, config) {
                    var manifestreq = {
                     method: 'POST',
                     url: '/container/manifest/'+$scope.container_id,
                     headers: {
                       'Content-Type': 'application/json'
                     },
                     data: {
                         'token': data.token,
                         'tag': $scope.tag
                     }
                    };
                    //Container.manifest({'id': $scope.container_id},{'token': data.token, 'tag': $scope.tag}).$promise.then(function(data){
                    $http(manifestreq).success(function(data, status, headers, config) {
                        $scope.manifest = data;
                    });
                    var tagsreq = {
                     method: 'POST',
                     url: '/container/tags/'+$scope.container_id,
                     headers: {
                       'Content-Type': 'application/json'
                     },
                     data: {
                         'token': data.token
                     }
                    };
                    //Container.tags({'id': $scope.container_id},{'token': data.token}).$promise.then(function(data){
                    $http(tagsreq).success(function(data, status, headers, config) {
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

        $scope.show_log = function(build){
            var dockerlog = '';
            for(var i = 0;i < build.response.length;i++) {
                dockerlog += '<div>'+build.response[i]+'</div>';
            }
                $scope.dockerlog = dockerlog;
        };

        $scope.go_to_dockerfile = function(){
            location.replace('#/dockerfile/'+$scope.container_id);
        }
})
.controller('containerDockerFileCtrl',
    function ($scope, $route, $routeParams, $document, $http, Container, Config) {
        $scope.container_id = $routeParams.path;

        $scope.cmOption = {
            lineNumbers: true,
            indentWithTabs: true,
            mode: 'docker'
          };

        Config.get().$promise.then(function(config) {
            $scope.registry = config['registry'];
            $http.get('/container/'+$scope.container_id).success(function(data){
            //Container.get({'id': $scope.container_id}).$promise.then(function(data){
                $scope.container = data;
            });
        });
        $scope.go_to_info = function(){
            location.replace('#/container/'+$scope.container_id);
        }
        $scope.update_dockerfile = function() {
            var req = {
             method: 'POST',
             url: '/container/dockerfile/'+$scope.container_id,
             headers: {
               'Content-Type': 'application/json'
             },
             data: {'dockerfile': $scope.container.meta.Dockerfile, 'git': $scope.container.meta.git}
            };
            $http(req).success(function(data, status, headers, config) {
            //Container.dockerFile({'id': $scope.container_id},{'dockerfile': $scope.container.meta.Dockerfile}).$promise.then(function(data){
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
.controller('allcontainersCtrl',
    function ($scope, $route, Container) {
        Container.query_all().$promise.then(function(data) {
            $scope.containers = data;
        });
        $scope.show_container = function(data) {
             location.replace('#/container/'+data.id);
        };
})
.controller('containersCtrl',
    function ($scope, $route, $http, Container) {
        $scope.selected = undefined;
        Container.latest({}, function(data){
            $scope.latest = data;
        });
        $scope.get_containers = function(val) {
            return Container.search({},{'search': val}).$promise.then(function(data){
                return data.map(function(item){
                        return item.id;
                  });
            });
        }
        $scope.select = function(item, model, label) {
            //Container.get({'id': item}).$promise.then(function(data){
            $http.get('/container/'+item).success(function(data){
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

.controller('usermngtCtrl',
    function($scope, $rootScope, $routeParams, $log, $location, $window, Auth) {
    $scope.user = Auth.getUser();
})

.controller('userCtrl',
    function($scope, $rootScope, $routeParams, $log, $location, $window, Auth, User) {
        $scope.is_logged = false;

        $rootScope.$on('loginCtrl.login', function (event, user) {
           $scope.user = user;
           $scope.is_logged = true;
           if($scope.user.role && $scope.user.role == 'admin') {
               $scope.is_admin = true;
           }
        });

        $scope.search = function(query) {
            $location.url('/search?q='+encodeURIComponent(query));
        };

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
                if($scope.user.role && $scope.user.role == 'admin') {
                    $scope.is_admin = true;
                }
                Auth.setUser($scope.user);
            }
        });

})
.controller('loginCtrl',
    function ($scope, $rootScope, $route, $routeParams, $location, $window, Auth, User) {
        $scope.token = "";
        
        $scope.uid = "";
        $scope.password = "";
        $scope.authenticate = function() {
            User.authenticate({},{'uid':$scope.uid, 'password':$scope.password, 'token': $scope.token}).$promise.then(function(data){
                var user = data['user'];
                if($window.sessionStorage != null) {
                    $window.sessionStorage.token = data.token;
                }
                if(user['id'] !== undefined) {
                    Auth.setUser(user);
                    $rootScope.$broadcast('loginCtrl.login', user);
                    $location.search('token', null);
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

        if($routeParams.token != undefined) {
            $scope.token = $routeParams.token;
            $scope.authenticate();
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

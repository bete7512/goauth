I am implemneting modular go-authentication library
main idea is it is modular
modules either they can have their own routes,models,hooks,middlewares..
or they can be csrf, ratelimiter which they have to access gloabl routes or modules to be applied
    1, core module(default module) which will have basic authentication email and password unless it is disabled this have to work
    2, two factor authentication module(will have routes,models,hooks,middlewares)
    3, csrf protection module(middlewares and routes no models(unless we wanted))
    4, ratelimiter module(middlewares no models and routes (unless we wanted))
    5, admin module(will have routes,models,hooks,middlewares)
    ...... will be added in the future

and about storage.
we may implement some providers which will implement some kind of interfaces.
and also user can pass their own storage impplementation.
also there should be some kind of way to handle migrations.


main concern is
1, how can you handle best storage mecheanism
2, how can you handle best migrations
3, how can we have best hooks handling the current one is not that much good i believe
4, think about how can we apply middlewares from modules like csrf or ratelimiter to modules and all routes comes from each module are route in each module need to be given uniue name
5, think as an architect and try to come with better architecture


and implement current unfinished impelmentation
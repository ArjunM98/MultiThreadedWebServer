# Multi-Threaded WebServer

A simple multi-threaded web server with caching capabilities used to server static web content 

The server is initialized with a fixed-size pool of worker threads used to serve requests. Each thread is blocked until there is an HTTP request to handle. When there are multiple HTTP requests available each request is handled in a FIFO order. 

For more information on the following multi-threaded server, refer to the following design documents: 
 - [Basic multi-threaded server](https://www.eecg.utoronto.ca/~ashvin/courses/ece344/current/lab4.html)
 - [Caching capabilites](https://www.eecg.utoronto.ca/~ashvin/courses/ece344/current/lab5.html) 

## Running the webserver

``./server port nr_threads max_requests max_cache_size``

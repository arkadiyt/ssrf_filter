FROM ruby:3.0.3

RUN apt update && apt-get install -y vim

WORKDIR ssrf_filter
COPY Gemfile ssrf_filter.gemspec .
COPY lib/ssrf_filter/version.rb lib/ssrf_filter/version.rb
RUN bundle update
COPY . .
CMD /bin/bash

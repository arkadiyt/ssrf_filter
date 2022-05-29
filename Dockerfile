FROM ruby:2.6.0

RUN apt update && apt-get install -y vim

WORKDIR app
COPY Gemfile ssrf_filter.gemspec .
COPY lib/ssrf_filter/version.rb lib/ssrf_filter/version.rb
RUN bundle update
ENV CI=1
COPY . .

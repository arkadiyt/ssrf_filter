FROM ruby:3.4.9

RUN apt update && apt-get install -y vim tmux tig

WORKDIR app
COPY Gemfile ssrf_filter.gemspec .
COPY lib/ssrf_filter/version.rb lib/ssrf_filter/version.rb
RUN bundle install
ENV CI=1

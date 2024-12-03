FROM python:3.12-slim

RUN apt update && apt install -y \
    git \
    && rm -rf /var/lib/apt/lists/*

RUN git clone https://gitlab.com/exploit-database/exploitdb.git /opt/exploitdb
RUN ln -sf /opt/exploitdb/searchsploit /usr/local/bin/searchsploit

WORKDIR /cmsmap

COPY . .

RUN sed -i 's|edbtype = apt|edbtype = GIT|' /cmsmap/cmsmap/cmsmap.conf
RUN sed -i 's|edbpath = /usr/share/exploitdb/|edbpath = /opt/exploitdb/|' /cmsmap/cmsmap/cmsmap.conf

RUN mkdir /cmsmap/cmsmap/tmp && \
    git clone https://github.com/wordpress/wordpress /cmsmap/cmsmap/tmp/wordpress && \
    git clone https://github.com/joomla/joomla-cms /cmsmap/cmsmap/tmp/joomla && \
    git clone https://github.com/drupal/drupal /cmsmap/cmsmap/tmp/drupal && \
    git clone https://github.com/moodle/moodle /cmsmap/cmsmap/tmp/moodle


ENTRYPOINT [ "python", "cmsmap.py" ]

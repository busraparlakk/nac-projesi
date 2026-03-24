FROM freeradius/freeradius-server:latest-3.2

# Default siteleri ve kullanmadığımız modülleri kaldır
RUN rm -f /etc/freeradius/sites-enabled/default \
    && rm -f /etc/freeradius/sites-enabled/inner-tunnel \
    && rm -f /etc/freeradius/mods-enabled/eap

# Config dosyalarını kopyala
COPY config/radiusd.conf /etc/freeradius/radiusd.conf
COPY config/clients.conf /etc/freeradius/clients.conf
COPY config/mods-available/sql /etc/freeradius/mods-available/sql
COPY config/mods-available/rest /etc/freeradius/mods-available/rest
COPY config/mods-enabled/sql /etc/freeradius/mods-enabled/sql
COPY config/mods-enabled/rest /etc/freeradius/mods-enabled/rest
COPY config/sites-available/nac /etc/freeradius/sites-available/nac
COPY config/sites-enabled/nac /etc/freeradius/sites-enabled/nac

# Doğru izinleri ver
RUN chmod 640 /etc/freeradius/radiusd.conf \
    && chmod 640 /etc/freeradius/clients.conf \
    && chmod 640 /etc/freeradius/mods-available/sql \
    && chmod 640 /etc/freeradius/mods-available/rest \
    && chmod 640 /etc/freeradius/mods-enabled/sql \
    && chmod 640 /etc/freeradius/mods-enabled/rest \
    && chmod 640 /etc/freeradius/sites-available/nac \
    && chmod 640 /etc/freeradius/sites-enabled/nac \
    && chown freerad:freerad /etc/freeradius/radiusd.conf \
    && chown freerad:freerad /etc/freeradius/clients.conf \
    && chown freerad:freerad /etc/freeradius/mods-available/sql \
    && chown freerad:freerad /etc/freeradius/mods-available/rest \
    && chown freerad:freerad /etc/freeradius/mods-enabled/sql \
    && chown freerad:freerad /etc/freeradius/mods-enabled/rest \
    && chown freerad:freerad /etc/freeradius/sites-available/nac \
    && chown freerad:freerad /etc/freeradius/sites-enabled/nac
server_ip=127.0.0.1

pkg bash wazuh-indexer wazuh-server wazuh-dashboard

openssl req -x509 -batch -nodes -days 365 -newkey rsa:2048 -subj "/C=US/ST=California/CN=Wazuh/" -keyout /var/ossec/etc/sslmanager.key -out /var/ossec/etc/sslmanager.cert
chmod 640 /var/ossec/etc/sslmanager.key
chmod 640 /var/ossec/etc/sslmanager.cert

cp /etc/localtime /var/ossec/etc
cp var/ossec/etc/ossec.conf /var/ossec/etc
cp usr/local/etc/beats/filebeat.yml /usr/local/etc/beats/
cp usr/local/etc/logstash/logstash.conf /usr/local/etc/logstash/
cp /usr/local/etc/wazuh-server/wazuh-template.json /usr/local/etc/logstash/
cp usr/local/etc/opensearch/opensearch.yml /usr/local/etc/opensearch/opensearch.yml
cp usr/local/etc/opensearch-dashboards/opensearch_dashboards.yml /usr/local/etc/opensearch-dashboards/
cp etc/hosts /etc/
cp root/bootstrap.sh /root/

sed -e "s,%%SERVER_IP%%,${server_ip},g" -i "" /usr/local/etc/beats/filebeat.yml
sed -e "s,%%SERVER_IP%%,${server_ip},g" -i "" /usr/local/etc/logstash/logstash.conf
sed -e "s,%%SERVER_IP%%,${server_ip},g" -i "" /usr/local/etc/opensearch/opensearch.yml
sed -e "s,%%SERVER_IP%%,${server_ip},g" -i "" /usr/local/etc/opensearch-dashboards/opensearch_dashboards.yml
sed -e "s,%%SERVER_IP%%,${server_ip},g" -i "" /etc/hosts
sed -e "s,%%SERVER_IP%%,${server_ip},g" -i "" /root/bootstrap.sh

cd /usr/local/logstash/bin; sh -c 'JAVA_HOME=/usr/local/openjdk17 ./logstash-plugin install logstash-output-opensearch'
cd /usr/local/etc/opensearch/opensearch-security; sh -c 'for i in $(ls *.sample ) ; do cp -p ${i} $(echo ${i} | sed "s|.sample||g") ; done'

mkdir -p /usr/local/etc/opensearch-dashboards/certs/
mkdir -p /usr/local/etc/opensearch/certs/
cd /root/; fetch "https://people.freebsd.org/~acm/ports/wazuh/wazuh-gen-certs.tar.gz"
cd /root/; tar xvfz wazuh-gen-certs.tar.gz
echo 'dashboard_ip="${server_ip}"' > /root/wazuh-gen-certs/dashboard.lst
echo 'indexer1_ip="${server_ip}"' > /root/wazuh-gen-certs/indexer.lst
echo 'server1_ip="${server_ip}"' > /root/wazuh-gen-certs/server.lst
cd /root/wazuh-gen-certs; echo y | sh gen-certs.sh

chmod 660 /var/ossec/etc/ossec.conf
chown root:wazuh /var/ossec/etc/ossec.conf

cp /root/wazuh-gen-certs/wazuh-certificates/admin.pem /usr/local/etc/opensearch/certs/
chmod 640 /usr/local/etc/opensearch/certs/admin.pem
chown opensearch:opensearch /usr/local/etc/opensearch/certs/admin.pem
cp /root/wazuh-gen-certs/wazuh-certificates/admin-key.pem /usr/local/etc/opensearch/certs/
chmod 640 /usr/local/etc/opensearch/certs/admin-key.pem
chown opensearch:opensearch /usr/local/etc/opensearch/certs/admin-key.pem
cp /root/wazuh-gen-certs/wazuh-certificates/indexer1.pem /usr/local/etc/opensearch/certs/
chmod 640 /usr/local/etc/opensearch/certs/indexer1.pem
chown opensearch:opensearch /usr/local/etc/opensearch/certs/indexer1.pem
cp /root/wazuh-gen-certs/wazuh-certificates/indexer1-key.pem /usr/local/etc/opensearch/certs/
chmod 640 /usr/local/etc/opensearch/certs/indexer1-key.pem
chown opensearch:opensearch /usr/local/etc/opensearch/certs/indexer1-key.pem
cp /root/wazuh-gen-certs/wazuh-certificates/root-ca.pem /usr/local/etc/opensearch/certs/
chmod 640 /usr/local/etc/opensearch/certs/root-ca.pem
chown opensearch:opensearch /usr/local/etc/opensearch/certs/root-ca.pem

cp /root/wazuh-gen-certs/wazuh-certificates/dashboard.pem /usr/local/etc/opensearch-dashboards/certs/
chmod 640 /usr/local/etc/opensearch-dashboards/certs/dashboard.pem
chown www:www /usr/local/etc/opensearch-dashboards/certs/dashboard.pem
cp /root/wazuh-gen-certs/wazuh-certificates/dashboard-key.pem /usr/local/etc/opensearch-dashboards/certs/
chmod 640 /usr/local/etc/opensearch-dashboards/certs/dashboard-key.pem
chown www:www /usr/local/etc/opensearch-dashboards/certs/dashboard-key.pem
cp /root/wazuh-gen-certs/wazuh-certificates/root-ca.pem /usr/local/etc/opensearch-dashboards/certs/
chmod 640 /usr/local/etc/opensearch-dashboards/certs/root-ca.pem
chown www:www /usr/local/etc/opensearch-dashboards/certs/root-ca.pem

sysrc wazuh_manager_enable=YES
sysrc filebeat_enable=YES
sysrc logstash_enable=YES
sysrc opensearch_enable=YES
sysrc opensearch_dashboards_enable=YES
sysrc opensearch_dashboards_syslog_output_enable=YES

service opensearch start

#RDR udp 1514 1514
#RDR tcp 1515 1515
#RDR tcp 5601 5601
#RDR tcp 55000 55000

sh /root/bootstrap.sh
rm /root/bootstrap.sh

service wazuh-manager start
service filebeat start
service logstash start
service opensearch-dashboards start

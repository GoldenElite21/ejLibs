import ldap3,datetime,re,pytz
from ldap3 import SUBTREE, MODIFY_REPLACE, MODIFY_DELETE
from ldap3.extend.microsoft.addMembersToGroups import ad_add_members_to_groups as addUsersToGroups
from ldap3.extend.microsoft.removeMembersFromGroups import ad_remove_members_from_groups as removeUsersFromGroups
from datetime import date,datetime,timedelta

class SimpleAD:
  def __init__(self, server, username, password, base):
    self.server = server
    self.username = username
    self.password = password

    self.conn = self.gen_conn(self.server)

    self.base   = base
    self.searchParamsBase = {
      'search_base'   : self.base,
      'search_scope'  : SUBTREE,
    }
    self.searchParamsPaged = self.searchParamsBase.copy()
    self.searchParamsPaged.update({
      'paged_size'    : 1000,
      'generator'     : False
    })

    self.dnToCN = {}
    self.cnToDN = {}

    self.mappingFails = 0
    self.allMappings = False

    self.dcList = []
    self.currTime = datetime.now()
    self.epoch_start = datetime(year=1601, month=1, day=1)
    self.epoch_start = self.epoch_start.replace(tzinfo=pytz.utc).astimezone(pytz.timezone('America/Detroit'))

  def get_cn(self, dn):
    dn = str(dn)
    if '=' in dn:
      if dn not in self.dnToCN:
        self.mapping_failed()
        if dn not in self.dnToCN:
          self.dnToCN[dn] = '' + dn.split(',')[0].split('=')[1]
          self.cnToDN[self.dnToCN[dn]] = dn 
      dn = self.dnToCN[dn]
    return dn

  def get_dn(self, cn):
    cn = str(cn)
    if '=' not in cn:
      if cn not in self.cnToDN:
        self.mapping_failed()
        if cn not in self.cnToDN:
          searchParams = self.searchParamsBase.copy()
          searchParams['search_filter'] = '(cn=%s)' % filter_format(cn)
          self.conn.search(**searchParams)
          try:
            self.cnToDN[cn] = str(self.conn.entries[0].entry_dn)
            self.dnToCN[self.cnToDN[cn]] = cn
          except:
            return cn
      cn = self.cnToDN[cn]
    return cn

  def mapping_failed(self):
    self.mappingFails += 1
    if(self.mappingFails >= 50 and (not self.allMappings)):
      self.get_filter_results('cn=*')
      self.allMappings = True


  def convert_timestamp(self, timestamp, json_safe=False, str_format="%x %X"):
    try:
      timestamp = int(timestamp)
      if timestamp == 0:
        return None
      seconds_since_epoch = timestamp / 10 ** 7
      converted_timestamp = self.epoch_start + timedelta(seconds=seconds_since_epoch)

    except ValueError:
      converted_timestamp = datetime.strptime(timestamp.split(".")[0], "%Y%m%d%H%M%S")

    if json_safe:
      converted_timestamp = converted_timestamp.strftime(str_format)

    return converted_timestamp


  def filter_format(self, dn):
    ##https://www.rlmueller.net/CharactersEscaped.htm
    replacements = { '*':'\\2A', '(':'\\28', ')':'\\29', '#':'\#', '+':'\+', '<':'\<', '>':'\>', ';':'\;', '"':'\"' }
    for original, replacement in replacements.items():
      dn = dn.replace(original, replacement)
    return dn

  def get_current_members(self, myGroup, objectType='User', attrsToPull=['dn'], recursedGroups=[]):
    #if you want users at base, just do self.get_filter_results(&(objectClass=user)(memberOf=(self.get_dn(myGroup)))
    if isinstance(attrsToPull, str):
      attrsToPull = [attrsToPull]

    myGroup = self.get_dn(myGroup)

    attrsToSearch = ['objectClass','cn']
    attrsToSearch = attrsToSearch + list(set(attrsToPull) - set(attrsToSearch) - set(['dn']))
    results = []

    filterType = '(|(objectClass=user)(objectClass=group))' if objectType == 'User' else '(objectClass=group)'
    myFilter = '(&{}(memberOf={}))'.format(filterType,self.filter_format(myGroup))

    entries = self.get_filter_results(myFilter, attrsToSearch)

    for entry in entries:
      if objectType == 'User': #returning user objects
        if 'group' in entry['objectClass']: #found group while looking for user
          if entry['dn'] not in recursedGroups: #Don't double work
            recursedGroups.append(entry['dn'])
            recursedResults = self.get_current_members(entry['dn'], objectType, attrsToPull, recursedGroups)
            results.extend(x for x in recursedResults if x not in results)
        elif len(attrsToPull) > 1: #attrs, therefore list of dict data
          results.append(entry)
        elif entry[attrsToPull[0]] not in results: #no attrs, therefore list of str(dn)
          results.append(entry[attrsToPull[0]])
      elif objectType == 'Group': #Return groups
        if 'group' in entry['objectClass']: #At base level only
          results.append(entry[attrsToPull[0]])

    return results

  def get_filter_results(self, myFilter, attrsToPull=['dn']):
    if isinstance(attrsToPull, str):
      attrsToPull = [attrsToPull]
    results = []
    attrsToSearch = ['cn']
    attrsToSearch = attrsToSearch + list(set(attrsToPull) - set(attrsToSearch) - set(['dn']))

    searchParameters = self.searchParamsPaged.copy()
    searchParameters.update({
      'search_filter' : myFilter,
      'attributes'    : attrsToSearch,
    })

    entry_generator = self.conn.extend.standard.paged_search(**searchParameters)
    entries = [i for i in entry_generator if i['type'] == 'searchResEntry']

    for entry in entries:
      try:
        self.cnToDN[entry['attributes']['cn']] = entry['dn']
        self.dnToCN[entry['dn']] = entry['attributes']['cn']
      except:
        pass
      if len(attrsToPull) > 1:
        if not any(data.get('dn', 'N/A') == entry['dn'] for data in results):
          tempDict = {}
          tempDict['dn'] = entry['dn']
          for attr in attrsToPull:
            tempDict[attr] = entry['attributes'][attr]
          results.append(tempDict)
      elif any(attr in ['dn'] for attr in attrsToPull):
        results.append(entry[attrsToPull[0]])
      else:
        results.append(entry['attributes'][attrsToPull[0]]) 

    return results

  def get_domain_controllers(self):
    if not self.dcList:
      self.dcList = self.get_filter_results('(&(objectCategory=computer)(userAccountControl:1.2.840.113556.1.4.803:=8192))', 'dNSHostName')
      self.dcList = sorted([x.lower() for x in self.dcList])

    return self.dcList

  def get_filter_results_each_dc(self, myFilter, attrsToPull=['dn'], intersect=True):
    connTemp = self.conn
    results = []

    if len(self.dcList) < 1:
      self.get_domain_controllers()

    if isinstance(attrsToPull, str):
      attrsToPull = [attrsToPull]

    for dc in self.dcList:
      self.conn = self.gen_conn(dc)
      if intersect: #IE: grab where DCs match
        if self.dcList.index(dc) == 0:
          results = self.get_filter_results(myFilter, attrsToPull)
        elif results:
          resultsInThisDC = self.get_filter_results(myFilter, attrsToPull)
          results = [x for x in resultsInThisDC if x in results]
      else:
        results = list(set(results) | set(self.get_filter_results(myFilter, attrsToPull)))
      self.conn.unbind()

    self.conn = connTemp
    return results

  def gen_time_filter(self,timeFilters,minutesFromNow=0):
    filetimeFilters = ['pwdlastset','accountexpires','lastlogon','lastlogontimestamp','lastpwdset']
    myFilter = ''

    if isinstance(timeFilters, str):
      timeFilters = {'filter':timeFilters, 'minutesFromNow':minutesFromNow}

    if isinstance(timeFilters, dict):
      timeFilters = [timeFilters]

    if (len(timeFilters) >= 2):
      myFilter += '&'
    for timeFilter in timeFilters:
      if re.sub(r'[^a-z]+', '', timeFilter['filter'].lower()) in filetimeFilters:
        deltaTime = str(int((self.currTime\
                         + timedelta(minutes=timeFilter['minutesFromNow'])\
                         - datetime(1601,1,1)\
                        ).total_seconds()*10000000))
      else:
        t = self.currTime+timedelta(minutes=minutesFromNow)
        deltaTime = t.strftime('%Y%m%d%H%M') + '00.0Z'
      temp = timeFilter['filter'] + deltaTime
      if (len(timeFilters) >= 2):
        temp = '(' + temp + ')'
      myFilter += temp

    myFilter = '(' + myFilter + ')'

    return myFilter

  def get_uac_mapping(self, uac, mapping):
    #https://docs.microsoft.com/en-us/troubleshoot/windows-server/identity/useraccountcontrol-manipulate-account-properties
    uacDict = {
      'SCRIPT':1,
      'ACCOUNTDISABLE':2,
      'HOMEDIR_REQUIRED':4,
      'HOMEDIR_REQUIRED':8,
      'LOCKOUT':16,
      'PASSWD_NOTREQD':32,
      'PASSWD_CANT_CHANGE':64,
      'ENCRYPTED_TEXT_PWD_ALLOWED':128,
      'TEMP_DUPLICATE_ACCOUNT':256,
      'NORMAL_ACCOUNT':512,
      'INTERDOMAIN_TRUST_ACCOUNT':2048,
      'WORKSTATION_TRUST_ACCOUNT':4096,
      'SERVER_TRUST_ACCOUNT':8192,
      'DONT_EXPIRE_PASSWORD':65536,
      'MNS_LOGON_ACCOUNT':131072,
      'SMARTCARD_REQUIRED':262144,
      'TRUSTED_FOR_DELEGATION':524288,
      'NOT_DELEGATED':1048576,
      'USE_DES_KEY_ONLY':2097152,
      'DONT_REQ_PREAUTH':4194304,
      'PASSWORD_EXPIRED':8388608,
      'TRUSTED_TO_AUTH_FOR_DELEGATION':16777216,
      'PARTIAL_SECRETS_ACCOUNT':67108864
    }
    return ((uac & uacDict[mapping]) != 0)


  def addToGroup(self, addition, group):
    return str(addUsersToGroups(self.conn, addition, group, raise_error=True, fix=True))

  def gen_conn(self, server):
    server = ldap3.Server(server)
    return ldap3.Connection(server, user=self.username, password=self.password, auto_bind=True)




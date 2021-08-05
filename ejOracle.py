import cx_Oracle

class SimpleOracle:
  def __init__(self, username, password, instance):
    self.instance = instance
    self.username = username
    self.password = password
    self.connect()

  def connect(self):
    conn_str = self.username + u'/' + self.password + u'@' + self.instance
    self.conn = cx_Oracle.connect(conn_str)

  def disconnect(self):
    try:
      self.conn.close()
    except:
      pass

  def pull_dict(self, sql = [], attrs=False, array=False):
    results = {} if attrs else []
    for row in self.pull(sql):
      if len(row) == 1: #one col
        results.append(row[0])
      elif array: #want array back
        if row[0] in results:
          results[row[0]].append(row[1]) #if user is found twice, append to array
        else:
          results[row[0]] = [row[1]] #otherwise, initalize array
      else:
        results[row[0]] = row[1] #otherwise, 1:1 mapping
    return results

  def pull(self, sql, binds=[]):
    results = []
    c = self.conn.cursor()
    if isinstance(sql, str):
      sql = [sql]
    if isinstance(binds, str):
      binds = [binds]
    for query in sql:
      if binds:
        c.execute(query, binds)
      else:
        c.execute(query)
      results.extend(row for row in c)
    return results

  def gen_class_sql(self, classes):
    sql = ("select unique gwkiden.f_external_user_from_pidm(sfrstcr_pidm) username"
           " from ssbsect, sfrstcr"
           " where (")

    if isinstance(classes, str):
      classes = [classes]
    first = True
    for my_class in classes:
      if not first:
        sql += ' or '
      else:
        first = False
      subj = re.sub('[^a-zA-Z]+','',my_class).upper() #You have to have a subject at least
      sql += "(ssbsect_subj_code = '" + subj + "'"
      if re.search(r'\d',my_class):
        numb = re.sub('[^0-9]+','',my_class)
        sql += " and ssbsect_crse_numb = '" + numb + "'"
      sql += ")"

    sql += (")"
            " and ssbsect_ssts_code = 'A'"
            " and ssbsect_term_code = (select gtvsdax_external_code from gtvsdax where gtvsdax_internal_code = 'REGCURTERM' and gtvsdax_internal_code_group = 'ASU')"
            " and sfrstcr_term_code = ssbsect_term_code"
            " and sfrstcr_crn = ssbsect_crn"
            " and sfrstcr_rsts_code like 'R%'")

    return sql


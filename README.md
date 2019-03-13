#使用 maven-assembly-plugin + maven-dependency-plugin 进行打包的示例


### 下载 Java Service Wrapper ：

https://wrapper.tanukisoftware.com/doc/english/download.jsp#stable

### 发布到本地Maven仓库 ：

``` 
mvn deploy:deploy-file -DgroupId=com.tanukisoftware -DartifactId=wrapper-delta-pack -Dversion=3.5.37 -Dpackaging=zip -Dfile=G:\wrapper-delta-pack-3.5.37.zip -Durl=http://127.0.0.1:8081/repository/maven-releases/ -DrepositoryId=nexus-releases

mvn deploy:deploy-file -DgroupId=com.tanukisoftware -DartifactId=wrapper-delta-pack -Dversion=3.5.37-pro -Dpackaging=zip -Dfile=G:\wrapper-delta-pack-3.5.37-pro.zip -Durl=http://127.0.0.1:8081/repository/maven-releases/ -DrepositoryId=nexus-releases

mvn deploy:deploy-file -DgroupId=com.tanukisoftware -DartifactId=wrapper-delta-pack -Dversion=3.5.37-st -Dpackaging=zip -Dfile=G:\wrapper-delta-pack-3.5.37-st.zip -Durl=http://127.0.0.1:8081/repository/maven-releases/ -DrepositoryId=nexus-releases
```

### 参考示例进行打包 ：
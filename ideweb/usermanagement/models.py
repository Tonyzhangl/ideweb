# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.db import models
from django.contrib.auth.models import BaseUserManager, AbstractBaseUser

# Create your models here.
class PermissionList(models.Model):
    name = models.CharField(max_length=64)
    url = models.CharField(max_length=255)

    def __unicode__(self):
        return '%s(%s)' %(self.name, self.url)

class RoleList(models.Model):
    name = models.CharField(max_length=50)
    permission = models.ManyToManyField(PermissionList,null=True,blank=True)

    def __unicode__(self):
        return self.name

class UserManager(BaseUserManager):
    def create_user(self,username,password,email,persionid):
        if not email:
            raise ValueError(u'用户必须填写邮箱信息')
        
        if not password:
            raise ValueError(u'密码必须填写')

        if not persionid:
            raise ValueError(u'身份证账号必须填写')
        
        user = self.model(
            username = username,
            email = self.normalize_email(email),
            password = password,
            persionid = persionid,
        )

        user.set_password(password)
        user.save(using=self._db)
        return user

    def create_superuser(self,username,email,password,persionid):
        user = self.create_user(username,email,password,persionid)
        user.is_active = True
        user.is_superuser = True
        user.save(using=self._db)
        return user

class User(AbstractBaseUser):
    username = models.CharField(max_length=50)
    password = models.CharField(required=True)
    email = models.EmailField(max_length=255)
    is_active = models.BooleanField(default=False)
    is_superuser = models.BooleanField(default=False)
    sex = models.CharField(max_length=2)
    role = models.ForeignKey(RoleList)
    persionid = models.CharField(max_length=50,unique=True, db_index=True)

    objects = UserManager()
    USERNAME_FIELD = 'username'
    REQUIRED_FIELDS = ['username','email', 'role', 'persionid']

    def has_permission(self, permission, obj=None):
        if self.is_active and self.is_superuser:
            return True


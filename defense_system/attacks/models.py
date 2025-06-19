from django.db import models

# Create your models here.


class AttackLog(models.Model):
    timestamp = models.DateTimeField(auto_now_add=True)
    source_ip = models.GenericIPAddressField()
    score = models.FloatField()
    status = models.CharField(max_length=50)

    def __str__(self):
        return f"{self.source_ip} ({self.score:.2f})"
    

class AttackCounter(models.Model):
    id = models.SmallAutoField(primary_key=True)
    count = models.IntegerField(default=0)
    last_emailed = models.IntegerField(default=0) 


# Generated by Django 5.1.6 on 2025-03-17 19:04

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('escan', '0008_alter_product_image_url'),
    ]

    operations = [
        migrations.AlterField(
            model_name='product',
            name='image_url',
            field=models.ImageField(upload_to='product_images'),
        ),
    ]

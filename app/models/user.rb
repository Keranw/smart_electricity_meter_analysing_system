class User < ActiveRecord::Base
  # Include default devise modules. Others available are:
  # :confirmable, :lockable, :timeoutable and :omniauthable
  devise :database_authenticatable, :registerable,
         :recoverable, :rememberable, :trackable, :validatable

  has_many :ftp_servers, dependent: :destroy
  has_many :sites
  has_many :billing_sites, through: :sites
  has_many :meters, through: :billing_sites
end

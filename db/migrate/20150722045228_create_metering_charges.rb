class CreateMeteringCharges < ActiveRecord::Migration
  def change
    create_table :metering_charges do |t|

      t.integer :charge_factory_id

      t.timestamps null: false
    end
  end
end
